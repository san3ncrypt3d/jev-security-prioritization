"""Analyze the v1.1 50k scale run -> results/analysis/scale_metrics.json (+ tables)."""

import gzip
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from jev_security import analysis as A  # noqa: E402
from jev_security import scale  # noqa: E402

recs = []
for p in sorted(scale.RAW.glob("*.jsonl.gz")):
    with gzip.open(p, "rt") as fh:
        for line in fh:
            r = json.loads(line)
            b = r.get("response_body") or {}
            a = b.get("answers") or {}
            recs.append(
                {
                    "idx": r["idx"],
                    "domain": r["domain"],
                    "attempt": r["attempt"],
                    "error": r["error"],
                    "http_status": r["http_status"],
                    "latency_ms": r["latency_ms"],
                    "start": r["utc_start"],
                    "end": r["utc_end"],
                    "model": b.get("model"),
                    "provider": b.get("provider"),
                    "input_tokens": (b.get("usage") or {}).get("input_tokens"),
                    "output_tokens": (b.get("usage") or {}).get("output_tokens"),
                    "cost": (b.get("usage") or {}).get("cost"),
                    "noul": (a.get("urgent") or {}).get("noul"),
                    "choice": (a.get("disposition") or {}).get("choice"),
                    "choice_conf": (a.get("disposition") or {}).get("confidence"),
                    "score": (a.get("exposure") or {}).get("score"),
                }
            )
R = pd.DataFrame(recs)
ok = R[R.error.isna()].drop_duplicates("idx", keep="last")
items = pd.DataFrame(scale.load()).set_index("idx")
D = ok.join(items[["ref_disp", "ref_exp", "ref_urgent"]], on="idx")
D["b0_disp"] = items.loc[D.idx, "b0"].map(lambda x: x["disposition"]).to_numpy()
D["b1_disp"] = items.loc[D.idx, "b1"].map(lambda x: x["disposition"]).to_numpy()
t = pd.to_datetime(R.start)
te = pd.to_datetime(R.end)
wall = (te.max() - t.min()).total_seconds()
# The first 200 findings were a pilot session; measure throughput on the main session separately.
sess = R.assign(t=t).groupby(pd.to_datetime(R.start).dt.floor("min")).size()
main_t = t[t > t.min() + pd.Timedelta(seconds=60)] if len(t) > 1000 else t
lat = ok.latency_ms.to_numpy()
rng = np.random.default_rng(0)
out = {
    "n_findings_planned": int(len(items)),
    "n_attempts": int(len(R)),
    "n_ok": int(len(ok)),
    "n_findings_without_success": int(len(items) - ok.idx.nunique()),
    "errors_by_status": R[R.error.notna()].groupby(R.http_status.fillna(-1).astype(int)).size().to_dict(),
    "error_messages": R[R.error.notna()].error.value_counts().head(5).to_dict(),
    "model_snapshots": ok.model.value_counts().to_dict(),
    "providers": ok.provider.value_counts().to_dict(),
    "input_tokens_total": int(ok.input_tokens.sum()),
    "input_tokens_mean": float(ok.input_tokens.mean()),
    "output_tokens_total": int(ok.output_tokens.sum()),
    "cost_total_usd": float(R.cost.fillna(0).sum()),
    "cost_ok_usd": float(ok.cost.sum()),
    "cost_per_1000_usd": float(ok.cost.mean() * 1000),
    "first_request_utc": str(t.min()),
    "last_response_utc": str(te.max()),
    "wall_minutes_incl_pilot_gap": wall / 60,
    "latency_ms": {
        q: float(np.percentile(lat, p))
        for q, p in [("p50", 50), ("p90", 90), ("p99", 99), ("max", 100), ("min", 0)]
    },
    "latency_ms_mean": float(lat.mean()),
    "latency_sample_ms": rng.choice(lat, size=min(5000, len(lat)), replace=False).round(1).tolist(),
}
main = R.assign(t=t, te=te)
main = main[main.t > t.min() + pd.Timedelta(seconds=30)]  # exclude the 200-request pilot session
mwall = (main.te.max() - main.t.min()).total_seconds()
out["main_session"] = {
    "requests": int(len(main)),
    "wall_minutes": mwall / 60,
    "requests_per_second": len(main) / mwall,
    "workers": scale.WORKERS,
}
out["wall_minutes"] = out["main_session"]["wall_minutes"]
tl = (
    main.assign(minute=((main.te - main.t.min()).dt.total_seconds() // 60).astype(int))
    .groupby("minute")
    .size()
)
out["throughput_timeline"] = [{"minute": int(m) + 1, "completed_cum": int(c)} for m, c in tl.cumsum().items()]
agree = {}
for dom, g in [("all", D), ("sca", D[D.domain == "sca"]), ("sast", D[D.domain == "sast"])]:
    det = g[g.ref_urgent.notna()]
    agree[dom] = {
        "n": int(len(g)),
        "jev_choice_acc": float((g.choice == g.ref_disp).mean()),
        "b0_acc": float((g.b0_disp == g.ref_disp).mean()),
        "b1_acc": float((g.b1_disp == g.ref_disp).mean()),
        "ref_distribution": g.ref_disp.value_counts().to_dict(),
        "jev_distribution": g.choice.value_counts().to_dict(),
        "urgency": {
            k: v
            for k, v in A.urgency_metrics(det.ref_urgent, det.noul).items()
            if k not in ("auc_ci95", "brier_ci95")
        },
        "score_mae": float(np.mean(np.abs(g.score - g.ref_exp))),
    }
out["agreement_uniform_sample"] = agree
out["calibration"] = {
    "n": agree["all"]["urgency"]["n"],
    "reliability": agree["all"]["urgency"]["reliability"],
    "ece_10bin": agree["all"]["urgency"]["ece_10bin"],
    "brier": agree["all"]["urgency"]["brier"],
}
(ROOT / "results/analysis/scale_metrics.json").write_text(json.dumps(out, indent=1, default=str) + "\n")
print(
    json.dumps(
        {k: v for k, v in out.items() if k not in ("latency_sample_ms", "throughput_timeline")},
        indent=1,
        default=str,
    )[:3000]
)
