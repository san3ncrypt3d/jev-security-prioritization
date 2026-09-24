"""Analyze the v1.2.1 frontier comparison -> results/analysis/frontier_metrics.json + table."""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from jev_security import analysis as A  # noqa: E402
from jev_security import frontier as F  # noqa: E402

cases = {c["case_id"]: c for c in F.pick_cases()}
rows = []
for p in sorted(F.RAW.glob("*.json")):
    r = json.loads(p.read_text())
    b = r.get("response_body") or {}
    u = b.get("usage") or {}
    c = cases[r["case_id"]]
    row = {
        "case_id": r["case_id"],
        "domain": r["domain"],
        "model": r["model"],
        "effort": r["effort"],
        "ok": r["error"] is None,
        "latency_ms": r["latency_ms"],
        "served_model": b.get("model"),
        "provider": b.get("provider"),
        "cost": u.get("cost"),
        "ref_disp": c["reference"]["disposition"],
        "ref_exp": c["reference"]["exposure"],
        "ref_urgent": c["reference"]["urgent"],
    }
    if r["model"] == F.JEV_MODEL:
        a = b.get("answers") or {}
        row.update(
            input_tokens=u.get("input_tokens"),
            output_tokens=u.get("output_tokens"),
            reasoning_tokens=0,
            valid=bool(a),
            p_urgent=(a.get("urgent") or {}).get("noul"),
            disposition=(a.get("disposition") or {}).get("choice"),
            exposure=(a.get("exposure") or {}).get("score"),
        )
    else:
        row.update(
            input_tokens=u.get("prompt_tokens"),
            output_tokens=u.get("completion_tokens"),
            reasoning_tokens=((u.get("completion_tokens_details") or {}).get("reasoning_tokens") or 0),
        )
        try:
            ans = json.loads(b["choices"][0]["message"]["content"])
            valid = (
                0 <= float(ans["urgent_probability"]) <= 1
                and ans["disposition"] in ("DEFER", "STANDARD", "ACCELERATED", "EMERGENCY", "REVIEW")
                and int(ans["exposure_level"]) in range(5)
            )
            row.update(
                valid=valid,
                p_urgent=float(ans["urgent_probability"]),
                disposition=ans["disposition"],
                exposure=float(ans["exposure_level"]),
            )
        except (KeyError, ValueError, TypeError, IndexError, json.JSONDecodeError):
            row.update(valid=False, p_urgent=None, disposition=None, exposure=None)
    rows.append(row)
D = pd.DataFrame(rows)
D.to_csv(ROOT / "results/normalized/frontier-v1.2_responses.csv", index=False)
jev_p50 = D[D.model == F.JEV_MODEL].latency_ms.median()
out, table = {"n_cases": len(cases), "models": {}}, []
for m, g in D.groupby("model"):
    v = g[g.valid]
    lat = g.latency_ms.to_numpy()
    res = {
        "requests": int(len(g)),
        "ok": int(g.ok.sum()),
        "valid_answers": int(g.valid.sum()),
        "providers": g.provider.value_counts().to_dict(),
        "served_models": g.served_model.value_counts().to_dict(),
        "latency_ms_p50": float(np.median(lat)),
        "latency_ms_p90": float(np.percentile(lat, 90)),
        "latency_ms_mean": float(lat.mean()),
        "latency_ms_max": float(lat.max()),
        "latency_ms_min": float(lat.min()),
        "latency_ratio_vs_jev_p50": float(np.median(lat) / jev_p50),
        "sequential_run_time_s_40_cases": float(lat.sum() / 1000),
        "input_tokens_mean": float(g.input_tokens.mean()),
        "output_tokens_mean": float(g.output_tokens.mean()),
        "reasoning_tokens_mean": float(g.reasoning_tokens.mean()),
        "cost_total_usd": float(g.cost.sum()),
        "cost_per_decision_usd": float(g.cost.mean()),
        "projected_cost_50k_usd": float(g.cost.mean() * 50000),
        "projected_sequential_hours_50k": float(lat.mean() * 50000 / 1000 / 3600),
        "agreement_descriptive_small_n": {
            "disposition_acc": float((v.disposition == v.ref_disp).mean()),
            "urgency_auc": A.auc(v.ref_urgent.astype(bool).to_numpy(), v.p_urgent.to_numpy()),
            "exposure_mae": float(np.mean(np.abs(v.exposure - v.ref_exp))),
            "chose_review": int((v.disposition == "REVIEW").sum()),
        },
    }
    out["models"][m] = res
    table.append(
        {
            "model": m,
            "n": res["requests"],
            "valid": res["valid_answers"],
            "p50_ms": res["latency_ms_p50"],
            "p90_ms": res["latency_ms_p90"],
            "max_ms": res["latency_ms_max"],
            "x_slower_than_jev": res["latency_ratio_vs_jev_p50"],
            "in_tok": res["input_tokens_mean"],
            "out_tok": res["output_tokens_mean"],
            "reason_tok": res["reasoning_tokens_mean"],
            "usd_per_decision": res["cost_per_decision_usd"],
            "usd_per_50k": res["projected_cost_50k_usd"],
            "hours_50k_sequential": res["projected_sequential_hours_50k"],
            "disp_acc_n40": res["agreement_descriptive_small_n"]["disposition_acc"],
            "urgency_auc_n40": res["agreement_descriptive_small_n"]["urgency_auc"],
        }
    )
T = pd.DataFrame(table).sort_values("p50_ms")
T.to_csv(ROOT / "results/tables/frontier_comparison.csv", index=False)
(ROOT / "results/tables/frontier_comparison.md").write_text(T.round(4).to_markdown(index=False) + "\n")
out["total_cost_usd"] = float(D.cost.sum())
out["latency_sample"] = {m: g.latency_ms.tolist() for m, g in D.groupby("model")}
(ROOT / "results/analysis/frontier_metrics.json").write_text(json.dumps(out, indent=1, default=str) + "\n")
pd.set_option("display.width", 250)
print(T.to_string(index=False, float_format=lambda x: f"{x:.4g}"))
print(f"total cost of comparison: ${out['total_cost_usd']:.4f}")
