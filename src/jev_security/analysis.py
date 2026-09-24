"""Normalization and pre-registered metrics.

Raw responses (results/raw/<run>/responses/*.json) are never modified.
``normalize`` derives one flat row per request_key; ``joined`` attaches every
case (a request can serve several cases) to its response.
"""

from __future__ import annotations

import json
import math

import numpy as np
import pandas as pd

from .provenance import ROOT
from .schemas import DISPOSITIONS, PRIORITY_RANK

BOOT_N = 2000
BOOT_SEED = 20260923
URGENT_T = 0.5


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize(run_id: str) -> pd.DataFrame:
    rows = []
    for p in sorted((ROOT / "results/raw" / run_id / "responses").glob("*.json")):
        rec = json.loads(p.read_text())
        body = rec.get("response_body") or {}
        a = body.get("answers") or {}
        u, d, e = a.get("urgent", {}), a.get("disposition", {}), a.get("exposure", {})
        complete = rec["error"] is None and all(k in a for k in ("urgent", "disposition", "exposure"))
        row = {
            "request_key": rec["request_key"],
            "attempt": rec["attempt"],
            "raw_file": p.name,
            "phase": rec["meta"].get("phase"),
            "utc_start": rec["utc_start"],
            "http_status": rec["http_status"],
            "error": rec["error"] if complete or rec["error"] else "missing answers",
            "ok": complete,
            "latency_ms": rec["latency_ms"],
            "response_id": body.get("id"),
            "model_snapshot": body.get("model"),
            "provider": body.get("provider"),
            "input_tokens": (body.get("usage") or {}).get("input_tokens"),
            "output_tokens": (body.get("usage") or {}).get("output_tokens"),
            "cost": (body.get("usage") or {}).get("cost"),
            "noul": u.get("noul"),
            "choice": d.get("choice"),
            "choice_confidence": d.get("confidence"),
            "score": e.get("score"),
            "score_confidence": e.get("confidence"),
        }
        for opt in DISPOSITIONS:
            row[f"p_{opt}"] = (d.get("probabilities") or {}).get(opt)
        for lvl in range(5):
            row[f"s_{lvl}"] = (e.get("probabilities") or {}).get(str(lvl))
        rows.append(row)
    return pd.DataFrame(rows)


def load_cases() -> list[dict]:
    out = []
    for d in ("sca", "sast"):
        out += json.loads((ROOT / f"data/{d}_cases.json").read_text())["cases"]
    return out


def joined(norm: pd.DataFrame) -> pd.DataFrame:
    ok = norm[norm.ok].drop_duplicates("request_key", keep="last").set_index("request_key")
    rows = []
    for c in load_cases():
        r = {
            "case_id": c["case_id"],
            "domain": c["domain"],
            "experiment": c["experiment"],
            "group": c["group"],
            "variant": c["variant"],
            "attribute": c["attribute"],
            "anchor": c["anchor_case_id"],
            "tags": ",".join(c["tags"]),
            "request_key": c["request_key"],
            "ref_disp": c["reference"]["disposition"],
            "ref_exp": c["reference"]["exposure"],
            "ref_urgent": c["reference"]["urgent"],
            "ref_exp_lo": c["reference"]["exposure_range"][0],
            "ref_exp_hi": c["reference"]["exposure_range"][1],
            "b0_disp": c["baselines"]["severity_only"]["disposition"],
            "b0_exp": c["baselines"]["severity_only"]["exposure"],
            "b0_urgent": c["baselines"]["severity_only"]["urgent"],
            "b1_disp": c["baselines"]["context_points"]["disposition"],
            "b1_exp": c["baselines"]["context_points"]["exposure"],
            "b1_urgent": c["baselines"]["context_points"]["urgent"],
            "b1_points": c["baselines"]["context_points"]["points"],
        }
        if c["request_key"] in ok.index:
            r.update(ok.loc[c["request_key"]].to_dict())
            r["answered"] = True
        else:
            r["answered"] = False
        rows.append(r)
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------


def rank(d):
    return PRIORITY_RANK.get(d)


def boot_ci(values_fn, n: int, seed: int = BOOT_SEED, reps: int = BOOT_N):
    rng = np.random.default_rng(seed)
    stats = []
    for _ in range(reps):
        idx = rng.integers(0, n, n)
        v = values_fn(idx)
        if v is not None and not (isinstance(v, float) and math.isnan(v)):
            stats.append(v)
    if not stats:
        return [None, None]
    return [float(np.percentile(stats, 2.5)), float(np.percentile(stats, 97.5))]


def auc(y: np.ndarray, s: np.ndarray):
    """Mann-Whitney AUC (ties count 1/2)."""
    y = np.asarray(y, bool)
    s = np.asarray(s, float)
    pos, neg = s[y], s[~y]
    if len(pos) == 0 or len(neg) == 0:
        return None
    from scipy.stats import rankdata

    r = rankdata(np.concatenate([pos, neg]))
    return float((r[: len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def ece(y, p, bins=10):
    y, p = np.asarray(y, float), np.asarray(p, float)
    edges = np.linspace(0, 1, bins + 1)
    total, table = 0.0, []
    for i in range(bins):
        m = (p >= edges[i]) & ((p < edges[i + 1]) if i < bins - 1 else (p <= 1))
        if m.sum():
            gap = abs(p[m].mean() - y[m].mean())
            total += m.sum() / len(p) * gap
            table.append(
                {
                    "bin": f"{edges[i]:.1f}-{edges[i + 1]:.1f}",
                    "n": int(m.sum()),
                    "mean_pred": float(p[m].mean()),
                    "observed": float(y[m].mean()),
                }
            )
    return float(total), table


def quadratic_kappa(a, b, k=5):
    a, b = np.asarray(a, int), np.asarray(b, int)
    o = np.zeros((k, k))
    for i, j in zip(a, b):
        o[i, j] += 1
    w = np.array([[(i - j) ** 2 for j in range(k)] for i in range(k)]) / (k - 1) ** 2
    e = np.outer(o.sum(1), o.sum(0)) / o.sum()
    return float(1 - (w * o).sum() / (w * e).sum())


def mcnemar_exact(a_correct, b_correct):
    from scipy.stats import binomtest

    a, b = np.asarray(a_correct, bool), np.asarray(b_correct, bool)
    n01, n10 = int((a & ~b).sum()), int((~a & b).sum())
    p = binomtest(n01, n01 + n10, 0.5).pvalue if n01 + n10 else 1.0
    return {
        "jev_right_baseline_wrong": n01,
        "jev_wrong_baseline_right": n10,
        "p_value": float(p),
        "p_value_sci": f"{p:.2e}",
    }


def disposition_metrics(ref: pd.Series, pred: pd.Series) -> dict:
    ref, pred = ref.reset_index(drop=True), pred.reset_index(drop=True)
    correct = (ref == pred).to_numpy()
    out = {"n": int(len(ref)), "accuracy": float(correct.mean()) if len(ref) else None}
    out["accuracy_ci95"] = boot_ci(lambda i: float(correct[i].mean()), len(ref)) if len(ref) else None
    f1s = []
    for c in DISPOSITIONS:
        tp = int(((pred == c) & (ref == c)).sum())
        fp = int(((pred == c) & (ref != c)).sum())
        fn = int(((pred != c) & (ref == c)).sum())
        if (ref == c).sum() == 0 and (pred == c).sum() == 0:
            continue
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1s.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
        out[f"precision_{c}"] = prec if tp + fp else None
        out[f"recall_{c}"] = rec if tp + fn else None
    out["macro_f1"] = float(np.mean(f1s)) if f1s else None
    both = [(rank(r), rank(p)) for r, p in zip(ref, pred) if rank(r) is not None and rank(p) is not None]
    det = [(r, p) for r, p in zip(ref, pred) if rank(r) is not None]
    out["n_determinate"] = len(det)
    out["false_escalation_rate"] = (sum(p > r for r, p in both) / len(det)) if det else None
    out["false_deprioritization_rate"] = (sum(p < r for r, p in both) / len(det)) if det else None
    out["review_on_determinate_rate"] = (sum(p == "REVIEW" for _, p in det) / len(det)) if det else None
    out["mean_abs_rank_error"] = float(np.mean([abs(p - r) for r, p in both])) if both else None
    return out


def confusion(ref: pd.Series, pred: pd.Series) -> pd.DataFrame:
    return pd.crosstab(
        pd.Categorical(ref, DISPOSITIONS),
        pd.Categorical(pred, DISPOSITIONS),
        rownames=["reference"],
        colnames=["predicted"],
        dropna=False,
    )


def urgency_metrics(y: pd.Series, p: pd.Series) -> dict:
    y = y.astype(bool).to_numpy()
    p = p.astype(float).to_numpy()
    pred = p >= URGENT_T
    tp, fp, fn = int((pred & y).sum()), int((pred & ~y).sum()), int((~pred & y).sum())
    out = {
        "n": int(len(y)),
        "n_urgent": int(y.sum()),
        "auc": auc(y, p),
        "auc_ci95": boot_ci(lambda i: auc(y[i], p[i]), len(y)),
        "precision@0.5": tp / (tp + fp) if tp + fp else None,
        "recall@0.5": tp / (tp + fn) if tp + fn else None,
        "accuracy@0.5": float((pred == y).mean()),
        "brier": float(np.mean((p - y) ** 2)),
        "brier_ci95": boot_ci(lambda i: float(np.mean((p[i] - y[i]) ** 2)), len(y)),
        "brier_base_rate": float(np.mean((y.mean() - y) ** 2)),
        "mean_p_urgent": float(p[y].mean()) if y.any() else None,
        "mean_p_not_urgent": float(p[~y].mean()) if (~y).any() else None,
    }
    out["ece_10bin"], out["reliability"] = ece(y, p)
    return out


def binary_metrics(y, pred) -> dict:
    y, pred = np.asarray(y, bool), np.asarray(pred, bool)
    tp, fp, fn = int((pred & y).sum()), int((pred & ~y).sum()), int((~pred & y).sum())
    return {
        "n": int(len(y)),
        "accuracy": float((pred == y).mean()),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def score_metrics(ref: pd.Series, score: pd.Series) -> dict:
    from scipy.stats import spearmanr

    r, s = ref.astype(float).to_numpy(), score.astype(float).to_numpy()
    rho = spearmanr(r, s).statistic if len(r) > 2 else None
    return {
        "n": int(len(r)),
        "mae": float(np.mean(np.abs(s - r))),
        "mae_ci95": boot_ci(lambda i: float(np.mean(np.abs(s[i] - r[i]))), len(r)),
        "bias_mean_signed": float(np.mean(s - r)),
        "spearman_rho": float(rho) if rho is not None else None,
        "exact_rounded": float(np.mean(np.clip(np.rint(s), 0, 4) == r)),
        "within_1": float(np.mean(np.abs(np.clip(np.rint(s), 0, 4) - r) <= 1)),
        "quadratic_kappa_rounded": quadratic_kappa(r.astype(int), np.clip(np.rint(s), 0, 4).astype(int)),
    }


def expected_rank(row) -> float:
    """Probability-weighted priority rank over the four non-REVIEW options (renormalized)."""
    ps = np.array([row[f"p_{d}"] or 0.0 for d in ("DEFER", "STANDARD", "ACCELERATED", "EMERGENCY")])
    return float((ps * np.arange(4)).sum() / ps.sum()) if ps.sum() else float("nan")
