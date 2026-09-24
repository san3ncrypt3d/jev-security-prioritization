"""Analyze experiment v2 -> results/analysis/v2_metrics.json and results/tables/v2_*.csv|md."""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from jev_security import v2_evidence as V  # noqa: E402

TAB = ROOT / "results/tables"
RAW = ROOT / "results/raw/v2"
F = {f["finding_id"]: f for f in json.loads((ROOT / "data/v2_findings.json").read_text())["findings"]}
MAN = json.loads((ROOT / "experiments/v2_manifest.json").read_text())
SUB = set(MAN["sonnet_subset"])
NOULS = [k for k, q in V.V2_QUESTIONS.items() if q["type"] == "noul"]


def load(pipe):
    out = {}
    for p in sorted((RAW / pipe).glob("*.json")) if (RAW / pipe).exists() else []:
        r = json.loads(p.read_text())
        out[r["finding_id"]] = r
    return out


jev_raw, son_raw = load("jev"), load("sonnet")
rows, probs = [], []
for fid, f in F.items():
    base = {
        "finding_id": fid,
        "set": f["set"],
        "lang": f["lang"],
        "urgent": f["reference"]["urgent"],
        "exposure": f["reference"]["exposure"],
        "in_subset": fid in SUB,
        "tricks": ",".join(f["tricks"]),
    }
    # oracle, severity, regex
    rows.append(
        {
            **base,
            "pipeline": "oracle",
            "ok": True,
            "pred_urgent": f["reference"]["urgent"],
            "route": False,
            **{f"f_{k}": f["truth"][k] for k in V.FIELDS},
        }
    )
    rows.append(
        {
            **base,
            "pipeline": "severity_only",
            "ok": True,
            "pred_urgent": f["severity"] in ("HIGH", "CRITICAL"),
            "route": False,
        }
    )
    rf = V.regex_fields(f["state"])
    rows.append(
        {
            **base,
            "pipeline": "regex",
            "ok": True,
            "pred_urgent": V.decide(rf, f)["urgent"],
            "route": False,
            **{f"f_{k}": rf[k] for k in V.FIELDS},
        }
    )
    # jev
    r = jev_raw.get(fid)
    ok = bool(r and r["error"] is None and (r["response_body"] or {}).get("answers"))
    if ok:
        ans = r["response_body"]["answers"]
        jf, unsure = V.jev_fields(ans)
        d = V.decide(jf, f)
        rows.append(
            {
                **base,
                "pipeline": "jev",
                "ok": True,
                "pred_urgent": d["urgent"],
                "route": unsure,
                "latency_ms": r["latency_ms"],
                "cost": r["response_body"]["usage"].get("cost"),
                "input_tokens": r["response_body"]["usage"].get("input_tokens"),
                "model": r["response_body"].get("model"),
                **{f"f_{k}": jf[k] for k in V.FIELDS},
            }
        )
        for k in NOULS:
            probs.append(
                {"pipeline": "jev", "set": f["set"], "field": k, "p": ans[k]["noul"], "y": f["truth"][k]}
            )
    else:
        rows.append({**base, "pipeline": "jev", "ok": False, "pred_urgent": None, "route": None})
    # sonnet
    r = son_raw.get(fid)
    if fid in SUB:
        try:
            assert r and r["error"] is None
            content = r["response_body"]["choices"][0]["message"]["content"]
            s = json.loads(content[content.find("{") : content.rfind("}") + 1])
            sf = {k: (float(s[k]) >= 0.5) for k in NOULS}
            sf.update(sanitization=s["sanitization"], auth=s["auth"])
            assert (
                sf["sanitization"] in V.CHOICE_FIELDS["sanitization"]
                and sf["auth"] in V.CHOICE_FIELDS["auth"]
            )
            unsure = any(V.NOUL_UNCERTAIN[0] <= float(s[k]) <= V.NOUL_UNCERTAIN[1] for k in NOULS)
            d = V.decide(sf, f)
            u = r["response_body"].get("usage") or {}
            rows.append(
                {
                    **base,
                    "pipeline": "sonnet",
                    "ok": True,
                    "pred_urgent": d["urgent"],
                    "route": unsure,
                    "latency_ms": r["latency_ms"],
                    "cost": u.get("cost"),
                    "input_tokens": u.get("prompt_tokens"),
                    "model": r["response_body"].get("model"),
                    **{f"f_{k}": sf[k] for k in V.FIELDS},
                }
            )
            for k in NOULS:
                probs.append(
                    {"pipeline": "sonnet", "set": f["set"], "field": k, "p": float(s[k]), "y": f["truth"][k]}
                )
        except (AssertionError, KeyError, ValueError, TypeError, IndexError, json.JSONDecodeError):
            rows.append(
                {
                    **base,
                    "pipeline": "sonnet",
                    "ok": False,
                    "pred_urgent": None,
                    "route": None,
                    "latency_ms": (r or {}).get("latency_ms"),
                }
            )
D = pd.DataFrame(rows)
P = pd.DataFrame(probs)
D.to_csv(ROOT / "results/normalized/v2_predictions.csv", index=False)

# routed variants
for base_pipe in ("jev", "sonnet"):
    g = D[(D.pipeline == base_pipe) & D.ok].copy()
    g["pipeline"] = base_pipe + "_routed"
    g["pred_urgent"] = g.pred_urgent.astype(bool) | g.route.astype(bool)
    D = pd.concat([D, g], ignore_index=True)

ORDER = ["oracle", "severity_only", "regex", "jev", "jev_routed", "sonnet", "sonnet_routed"]


def queue(df):
    df = df[df.ok]
    y = df.urgent.astype(bool).to_numpy()
    q = df.pred_urgent.astype(bool).to_numpy()
    return {
        "n": int(len(df)),
        "n_urgent": int(y.sum()),
        "queue": int(q.sum()),
        "queue_share": float(q.mean()),
        "urgent_caught": int((q & y).sum()),
        "urgent_missed": int((~q & y).sum()),
        "recall": float((q & y).sum() / y.sum()) if y.sum() else None,
        "precision": float((q & y).sum() / q.sum()) if q.sum() else None,
    }


out = {
    "n_findings": len(F),
    "sets": {s: int(sum(f["set"] == s for f in F.values())) for s in "AB"},
    "urgent": {s: int(sum(f["set"] == s and f["reference"]["urgent"] for f in F.values())) for s in "AB"},
    "sonnet_subset_n": len(SUB),
    "queue": {},
    "field_accuracy": {},
    "brier": {},
}
qrows, frows = [], []
for scope, mask in [
    ("A", D.set == "A"),
    ("B", D.set == "B"),
    ("all", D.set.notna()),
    ("subset_A", (D.set == "A") & D.in_subset),
    ("subset_B", (D.set == "B") & D.in_subset),
    ("subset_all", D.in_subset),
]:
    for pipe in ORDER:
        g = D[mask & (D.pipeline == pipe)]
        if not len(g) or (pipe.startswith("sonnet") and not scope.startswith("subset")):
            continue
        q = queue(g)
        q["failed"] = int((~g.ok).sum())
        out["queue"].setdefault(scope, {})[pipe] = q
        qrows.append({"scope": scope, "pipeline": pipe, **q})
    for pipe in ("regex", "jev", "sonnet"):
        g = D[mask & (D.pipeline == pipe) & D.ok]
        if not len(g) or (pipe == "sonnet" and not scope.startswith("subset")):
            continue
        acc = {}
        for k in V.FIELDS:
            truth = g.finding_id.map(lambda i, k=k: F[i]["truth"][k])
            acc[k] = float((g[f"f_{k}"] == truth).mean())
        acc["all_fields_correct"] = float(
            np.mean(
                [
                    all(r[f"f_{k}"] == F[r["finding_id"]]["truth"][k] for k in V.FIELDS)
                    for _, r in g.iterrows()
                ]
            )
        )
        out["field_accuracy"].setdefault(scope, {})[pipe] = acc
        frows.append({"scope": scope, "pipeline": pipe, "n": len(g), **acc})
for (pipe, s), g in P.groupby(["pipeline", "set"]):
    for k, h in g.groupby("field"):
        y = h.y.astype(float).to_numpy()
        out["brier"].setdefault(pipe, {}).setdefault(s, {})[k] = float(np.mean((h.p.to_numpy() - y) ** 2))

# Accuracy on the tricky cases (field-specific traps), set A + B
trap_field = {
    "second_order_source": "attacker_controlled",
    "opaque_helper": "sanitization",
    "misleading_comment": "sanitization",
    "misleading_todo": "sanitization",
    "non_auth_decorator": "auth",
    "unreachable_commented": "reachable",
    "unreachable_flag": "reachable",
    "unreachable_absent": "reachable",
    "test_path_without_test_word": "test_code",
}
trows = []
for trick, field in trap_field.items():
    for pipe in ("regex", "jev", "sonnet"):
        g = D[(D.pipeline == pipe) & D.ok & D.tricks.str.contains(trick)]
        if pipe == "sonnet":
            g = g[g.in_subset]
        if len(g):
            truth = g.finding_id.map(lambda i, field=field: F[i]["truth"][field])
            trows.append(
                {
                    "trap": trick,
                    "field": field,
                    "pipeline": pipe,
                    "n": len(g),
                    "accuracy": float((g[f"f_{field}"] == truth).mean()),
                }
            )
T = pd.DataFrame(trows)
out["traps"] = T.to_dict("records")

# latency / cost
cost = {}
for pipe in ("jev", "sonnet"):
    g = D[(D.pipeline == pipe) & D.ok]
    lat = g.latency_ms.astype(float).to_numpy()
    cost[pipe] = {
        "requests": int(len(g)),
        "failed": int((D[(D.pipeline == pipe)].ok == False).sum()),  # noqa: E712
        "models": g.model.value_counts().to_dict(),
        "latency_ms_p50": float(np.median(lat)),
        "latency_ms_p90": float(np.percentile(lat, 90)),
        "cost_total_usd": float(g.cost.sum()),
        "cost_per_finding_usd": float(g.cost.mean()),
        "input_tokens_mean": float(g.input_tokens.mean()),
    }
out["cost"] = cost

pd.DataFrame(qrows).to_csv(TAB / "v2_queue.csv", index=False)
(TAB / "v2_queue.md").write_text(pd.DataFrame(qrows).round(3).to_markdown(index=False) + "\n")
pd.DataFrame(frows).to_csv(TAB / "v2_field_accuracy.csv", index=False)
(TAB / "v2_field_accuracy.md").write_text(pd.DataFrame(frows).round(3).to_markdown(index=False) + "\n")
T.to_csv(TAB / "v2_traps.csv", index=False)
(TAB / "v2_traps.md").write_text(T.round(3).to_markdown(index=False) + "\n")
(ROOT / "results/analysis/v2_metrics.json").write_text(json.dumps(out, indent=1, default=str) + "\n")

pd.set_option("display.width", 220)
print(
    pd.DataFrame(qrows)[
        [
            "scope",
            "pipeline",
            "n",
            "n_urgent",
            "queue",
            "queue_share",
            "urgent_caught",
            "urgent_missed",
            "recall",
            "precision",
            "failed",
        ]
    ].to_string(index=False, float_format=lambda x: f"{x:.3f}")
)
print()
print(pd.DataFrame(frows).to_string(index=False, float_format=lambda x: f"{x:.3f}"))
print()
print(json.dumps(cost, indent=1))
