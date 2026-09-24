"""GATE 8: normalize raw responses and compute all pre-registered metrics.

    python scripts/analyze.py [--run-id run-v1.0.0]

Outputs (all derived, regenerable; raw data is never touched):
    results/normalized/<run>_responses.csv   one row per API request
    results/normalized/<run>_cases.csv       one row per case (joined to its response)
    results/analysis/metrics.json            every number reported in the blog
    results/tables/*.csv|md                  tables
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jev_security import analysis as A  # noqa: E402
from jev_security.provenance import load_hashes, sha256_file, verify_frozen  # noqa: E402
from jev_security.schemas import DISPOSITIONS  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--run-id", default="run-v1.0.0")
args = ap.parse_args()
RUN = args.run_id
TAB = ROOT / "results/tables"
TAB.mkdir(parents=True, exist_ok=True)
OUT = {}


def r(x, n=4):
    if isinstance(x, dict):
        return {k: r(v, n) for k, v in x.items()}
    if isinstance(x, list):
        return [r(v, n) for v in x]
    if isinstance(x, (float, np.floating)):
        return None if np.isnan(x) else round(float(x), n)
    if isinstance(x, np.integer):
        return int(x)
    return x


def table(df: pd.DataFrame, name: str, floatfmt=3):
    df.to_csv(TAB / f"{name}.csv", index=False)
    (TAB / f"{name}.md").write_text(df.round(floatfmt).to_markdown(index=False) + "\n")


changed = verify_frozen()
norm = A.normalize(RUN)
norm.to_csv(ROOT / f"results/normalized/{RUN}_responses.csv", index=False)
J = A.joined(norm)
J.to_csv(ROOT / f"results/normalized/{RUN}_cases.csv", index=False)
J = J[J.answered].copy()
J["rank_pred"] = J.choice.map(A.rank)
J["rank_ref"] = J.ref_disp.map(A.rank)
J["exp_rank"] = J.apply(A.expected_rank, axis=1)

# ---------------------------------------------------------------------------
# 1. Run / API summary
# ---------------------------------------------------------------------------
smoke = A.normalize("smoke")
allreq = pd.concat([norm.assign(run=RUN), smoke.assign(run="smoke")])
okreq = allreq[allreq.ok]
lat = okreq.latency_ms.to_numpy()
OUT["run"] = {
    "run_id": RUN,
    "frozen_artifacts_unchanged": not changed,
    "hashes": load_hashes()["sha256"],
    "manifest_sha256": sha256_file(ROOT / "experiments/experiment_manifest.json"),
    "requests_total_incl_smoke": int(len(allreq)),
    "requests_ok": int(allreq.ok.sum()),
    "requests_failed": int((~allreq.ok).sum()),
    "attempts_retried": int((allreq.attempt > 1).sum()),
    "model_snapshots": allreq.model_snapshot.value_counts().to_dict(),
    "providers": allreq.provider.value_counts().to_dict(),
    "input_tokens_total": int(okreq.input_tokens.sum()),
    "output_tokens_total": int(okreq.output_tokens.sum()),
    "input_tokens_mean": float(okreq.input_tokens.mean()),
    "input_tokens_min": int(okreq.input_tokens.min()),
    "input_tokens_max": int(okreq.input_tokens.max()),
    "output_tokens_mean": float(okreq.output_tokens.mean()),
    "cost_total_usd": float(okreq.cost.sum()),
    "cost_mean_per_request_usd": float(okreq.cost.mean()),
    "cost_per_1000_requests_usd": float(okreq.cost.mean() * 1000),
    "usd_per_million_input_tokens_observed": float(okreq.cost.sum() / okreq.input_tokens.sum() * 1e6),
    "latency_ms": {
        "p50": float(np.percentile(lat, 50)),
        "p90": float(np.percentile(lat, 90)),
        "p99": float(np.percentile(lat, 99)),
        "max": float(lat.max()),
        "min": float(lat.min()),
        "mean": float(lat.mean()),
    },
    "first_request_utc": okreq.utc_start.min(),
    "last_request_utc": okreq.utc_start.max(),
    "requests_by_phase": allreq.phase.value_counts().to_dict(),
    "cases_total": int(len(A.joined(norm))),
    "cases_answered": int(len(J)),
}

# ---------------------------------------------------------------------------
# 2. Primary analysis: main + contradiction (all determinate by construction)
# ---------------------------------------------------------------------------
P = J[J.experiment.isin(["main", "contradiction"])]
OUT["primary"] = {}
conf_rows = []
for dom in ["sca", "sast", "all"]:
    d = P if dom == "all" else P[P.domain == dom]
    res = {"n": int(len(d))}
    for name, col in [("jev", "choice"), ("b0_severity_only", "b0_disp"), ("b1_context_points", "b1_disp")]:
        res[name] = {"disposition": A.disposition_metrics(d.ref_disp, d[col])}
    res["jev"]["urgency"] = A.urgency_metrics(d.ref_urgent, d.noul)
    res["b0_severity_only"]["urgency"] = A.binary_metrics(d.ref_urgent, d.b0_urgent)
    res["b1_context_points"]["urgency"] = A.binary_metrics(d.ref_urgent, d.b1_urgent)
    res["jev"]["urgency"]["b1_points_auc"] = A.auc(
        d.ref_urgent.astype(bool).to_numpy(), d.b1_points.to_numpy()
    )
    res["jev"]["score"] = A.score_metrics(d.ref_exp, d.score)
    res["b0_severity_only"]["score"] = A.score_metrics(d.ref_exp, d.b0_exp)
    res["b1_context_points"]["score"] = A.score_metrics(d.ref_exp, d.b1_exp)
    jc = (d.choice == d.ref_disp).to_numpy()
    res["mcnemar_jev_vs_b0"] = A.mcnemar_exact(jc, (d.b0_disp == d.ref_disp).to_numpy())
    res["mcnemar_jev_vs_b1"] = A.mcnemar_exact(jc, (d.b1_disp == d.ref_disp).to_numpy())
    res["jev_choice_distribution"] = d.choice.value_counts().reindex(DISPOSITIONS, fill_value=0).to_dict()
    res["jev_mean_choice_confidence"] = float(d.choice_confidence.mean())
    res["jev_mean_score_confidence"] = float(d.score_confidence.mean())
    res["jev_mean_p_review"] = float(d.p_REVIEW.mean())
    # Choice calibration: selected-option probability vs correctness
    pmax = d[[f"p_{o}" for o in DISPOSITIONS]].max(axis=1).to_numpy()
    res["jev_choice_selected_prob_vs_correct"] = {
        "mean_selected_prob": float(pmax.mean()),
        "accuracy": float(jc.mean()),
        "ece_10bin": A.ece(jc, pmax)[0],
        "reliability": A.ece(jc, pmax)[1],
    }
    OUT["primary"][dom] = res
    for who, col in [("jev", "choice"), ("b0", "b0_disp"), ("b1", "b1_disp")]:
        cm = A.confusion(d.ref_disp, d[col])
        cm.to_csv(TAB / f"confusion_{dom}_{who}.csv")
    for sub in ["main", "contradiction"]:
        s = d[d.experiment == sub]
        conf_rows.append(
            {
                "domain": dom,
                "subset": sub,
                "n": len(s),
                "jev_acc": (s.choice == s.ref_disp).mean(),
                "b0_acc": (s.b0_disp == s.ref_disp).mean(),
                "b1_acc": (s.b1_disp == s.ref_disp).mean(),
                "jev_auc": A.auc(s.ref_urgent.astype(bool).to_numpy(), s.noul.to_numpy()),
                "jev_score_mae": np.mean(np.abs(s.score - s.ref_exp)),
            }
        )
subset_tab = pd.DataFrame(conf_rows)
table(subset_tab, "primary_by_subset")
OUT["primary_by_subset"] = subset_tab.to_dict("records")

rows = []
for dom in ["sca", "sast", "all"]:
    res = OUT["primary"][dom]
    for who in ["jev", "b0_severity_only", "b1_context_points"]:
        dm, um, sm = res[who]["disposition"], res[who]["urgency"], res[who]["score"]
        rows.append(
            {
                "domain": dom,
                "method": who,
                "n": dm["n"],
                "choice_acc": dm["accuracy"],
                "acc_ci_lo": dm["accuracy_ci95"][0],
                "acc_ci_hi": dm["accuracy_ci95"][1],
                "macro_f1": dm["macro_f1"],
                "false_escalation": dm["false_escalation_rate"],
                "false_deprioritization": dm["false_deprioritization_rate"],
                "review_on_determinate": dm["review_on_determinate_rate"],
                "urgency_auc": um.get("auc"),
                "urgency_recall": um.get("recall@0.5", um.get("recall")),
                "urgency_precision": um.get("precision@0.5", um.get("precision")),
                "score_mae": sm["mae"],
                "score_spearman": sm["spearman_rho"],
            }
        )
table(pd.DataFrame(rows), "primary_metrics")

# Per-reference-class breakdown (where Jev and the rubric disagree)
by_ref = pd.DataFrame(
    [
        {
            "domain": dom,
            "ref_disp": ref,
            "n": len(g),
            "jev_acc": (g.choice == ref).mean(),
            "mean_noul": g.noul.mean(),
            "mean_score": g.score.mean(),
            "modal_jev_choice": g.choice.mode().iloc[0],
            "jev_choices": json.dumps(g.choice.value_counts().to_dict()),
        }
        for (dom, ref), g in P.groupby(["domain", "ref_disp"])
    ]
)
table(by_ref, "primary_by_reference_class")
OUT["primary_by_reference_class"] = by_ref.to_dict("records")

# ---------------------------------------------------------------------------
# 3. Severity vs context (contradiction subset)
# ---------------------------------------------------------------------------
C = J[J.experiment == "contradiction"].copy()
C["b0_rank"] = C.b0_disp.map(A.rank)
C["moved_toward_context"] = np.where(
    C.variant == "high_severity_low_context", C.rank_pred < C.b0_rank, C.rank_pred > C.b0_rank
)
contra = C[
    [
        "case_id",
        "domain",
        "variant",
        "ref_disp",
        "ref_exp",
        "b0_disp",
        "b1_disp",
        "choice",
        "choice_confidence",
        "noul",
        "score",
        "p_REVIEW",
        "moved_toward_context",
    ]
]
table(contra, "contradiction_cases")
OUT["contradiction"] = {}
for (dom, kind), g in C.groupby(["domain", "variant"]):
    OUT["contradiction"][f"{dom}/{kind}"] = {
        "n": int(len(g)),
        "jev_acc": float((g.choice == g.ref_disp).mean()),
        "b0_acc": float((g.b0_disp == g.ref_disp).mean()),
        "b1_acc": float((g.b1_disp == g.ref_disp).mean()),
        "jev_moved_away_from_severity_toward_context": float(g.moved_toward_context.mean()),
        "mean_noul": float(g.noul.mean()),
        "mean_score": float(g.score.mean()),
        "jev_choices": g.choice.value_counts().to_dict(),
        "ref": g.ref_disp.value_counts().to_dict(),
    }

# ---------------------------------------------------------------------------
# 4. Inconsistent (conflicting sources) and missing evidence
# ---------------------------------------------------------------------------
M = J[J.experiment == "main"]
INC = J[J.experiment == "inconsistent"]
OUT["inconsistent"] = {}
for dom, g in INC.groupby("domain"):
    mm = M[M.domain == dom]
    OUT["inconsistent"][dom] = {
        "n": int(len(g)),
        "review_selected_rate": float((g.choice == "REVIEW").mean()),
        "mean_p_review": float(g.p_REVIEW.mean()),
        "main_mean_p_review": float(mm.p_REVIEW.mean()),
        "mean_choice_confidence": float(g.choice_confidence.mean()),
        "main_mean_choice_confidence": float(mm.choice_confidence.mean()),
        "jev_choices": g.choice.value_counts().to_dict(),
        "stakes_urgency_undetermined": int(g.ref_urgent.isna().sum()),
    }
table(
    INC[
        [
            "case_id",
            "domain",
            "attribute",
            "ref_disp",
            "ref_exp_lo",
            "ref_exp_hi",
            "ref_urgent",
            "choice",
            "p_REVIEW",
            "choice_confidence",
            "noul",
            "score",
        ]
    ],
    "inconsistent_cases",
)

MI = J[J.experiment == "missing"].copy()
anchor = MI[MI.variant == "known"].set_index("group")
rows = []
for _, x in MI[MI.variant != "known"].iterrows():
    a = anchor.loc[x.group]
    rows.append(
        {
            "domain": x.domain,
            "field": x.attribute,
            "mode": x.variant,
            "group": x.group,
            "ref_disp": x.ref_disp,
            "ref_review": x.ref_disp == "REVIEW",
            "stakes": ("urgency" if pd.isna(x.ref_urgent) else "defer_vs_standard")
            if x.ref_disp == "REVIEW"
            else "none",
            "anchor_choice": a.choice,
            "choice": x.choice,
            "changed": x.choice != a.choice,
            "selected_review": x.choice == "REVIEW",
            "correct": x.choice == x.ref_disp,
            "d_p_review": x.p_REVIEW - a.p_REVIEW,
            "d_conf": x.choice_confidence - a.choice_confidence,
            "d_noul": x.noul - a.noul,
            "d_score": x.score - a.score,
            "d_score_conf": x.score_confidence - a.score_confidence,
        }
    )
MD = pd.DataFrame(rows)
MD.to_csv(TAB / "missing_pairs.csv", index=False)
agg = (
    MD.groupby(["domain", "field", "mode"])
    .agg(
        n=("group", "size"),
        ref_review_rate=("ref_review", "mean"),
        selected_review=("selected_review", "mean"),
        choice_changed=("changed", "mean"),
        mean_d_p_review=("d_p_review", "mean"),
        mean_d_conf=("d_conf", "mean"),
        mean_d_noul=("d_noul", "mean"),
        mean_d_score=("d_score", "mean"),
    )
    .reset_index()
)
table(agg, "missing_summary")
OUT["missing"] = {
    "by_field_mode": agg.to_dict("records"),
    "overall": {
        "n_variants": int(len(MD)),
        "ref_review_rate": float(MD.ref_review.mean()),
        "jev_selected_review_rate": float(MD.selected_review.mean()),
        "jev_selected_review_when_ref_review": float(MD[MD.ref_review].selected_review.mean()),
        "jev_review_recall_urgency_stakes": float(MD[MD.stakes == "urgency"].selected_review.mean())
        if (MD.stakes == "urgency").any()
        else None,
        "n_urgency_stakes": int((MD.stakes == "urgency").sum()),
        "mean_d_p_review": float(MD.d_p_review.mean()),
        "mean_d_p_review_when_ref_review": float(MD[MD.ref_review].d_p_review.mean()),
        "mean_d_conf": float(MD.d_conf.mean()),
        "share_conf_decreased": float((MD.d_conf < 0).mean()),
        "choice_changed_rate": float(MD.changed.mean()),
        "accuracy_vs_rubric": float(MD.correct.mean()),
        "unknown_vs_omitted": MD.groupby("mode")[["selected_review", "d_p_review", "d_conf", "changed"]]
        .mean()
        .to_dict("index"),
    },
    "by_domain": MD.groupby("domain")[["selected_review", "d_p_review", "d_conf", "changed", "correct"]]
    .mean()
    .to_dict("index"),
}
# Pooled REVIEW recall/precision over every case with a REVIEW reference (missing + inconsistent)
RV = J[J.experiment.isin(["missing", "inconsistent"]) & (J.variant != "known")]
OUT["review_overall"] = {
    "n_ref_review": int((RV.ref_disp == "REVIEW").sum()),
    "jev_review_recall": float((RV[RV.ref_disp == "REVIEW"].choice == "REVIEW").mean()),
    "jev_review_selected_total": int((J.choice == "REVIEW").sum()),
    "jev_review_selected_on_any_determinate_case": int(
        ((J.choice == "REVIEW") & (J.ref_disp != "REVIEW")).sum()
    ),
    "max_p_review_any_case": float(J.p_REVIEW.max()),
    "p_review_quantiles_all_cases": {q: float(J.p_REVIEW.quantile(q)) for q in (0.5, 0.9, 0.99)},
}

# ---------------------------------------------------------------------------
# 5. Counterfactual attribute sensitivity
# ---------------------------------------------------------------------------
CF = J[J.experiment == "counterfactual"]
rows, per_pair = [], []
for (dom, attr), g in CF.groupby(["domain", "attribute"]):
    lo = g[g.variant == "low"].set_index("group")
    hi = g[g.variant == "high"].set_index("group").loc[lo.index]
    dn = (hi.noul - lo.noul).to_numpy()
    ds = (hi.score - lo.score).to_numpy()
    der = (hi.exp_rank - lo.exp_rank).to_numpy()
    dref = (hi.ref_exp - lo.ref_exp).to_numpy().astype(float)
    flips = (hi.choice != lo.choice).to_numpy()
    rflips = (hi.ref_disp != lo.ref_disp).to_numpy()
    for gid in lo.index:
        per_pair.append(
            {
                "domain": dom,
                "attribute": attr,
                "context": gid,
                "ctx_ref_exposure_low": lo.loc[gid, "ref_exp"],
                "ctx_ref_exposure_high": hi.loc[gid, "ref_exp"],
                "noul_low": lo.loc[gid, "noul"],
                "noul_high": hi.loc[gid, "noul"],
                "score_low": lo.loc[gid, "score"],
                "score_high": hi.loc[gid, "score"],
                "choice_low": lo.loc[gid, "choice"],
                "choice_high": hi.loc[gid, "choice"],
                "ref_low": lo.loc[gid, "ref_disp"],
                "ref_high": hi.loc[gid, "ref_disp"],
            }
        )
    row = {
        "domain": dom,
        "attribute": attr,
        "n_pairs": len(lo),
        "mean_d_noul": dn.mean(),
        "d_noul_ci_lo": A.boot_ci(lambda i, dn=dn: float(dn[i].mean()), len(dn))[0],
        "d_noul_ci_hi": A.boot_ci(lambda i, dn=dn: float(dn[i].mean()), len(dn))[1],
        "share_d_noul_positive": (dn > 0).mean(),
        "mean_d_score": ds.mean(),
        "d_score_ci_lo": A.boot_ci(lambda i, ds=ds: float(ds[i].mean()), len(ds))[0],
        "d_score_ci_hi": A.boot_ci(lambda i, ds=ds: float(ds[i].mean()), len(ds))[1],
        "mean_d_expected_priority_rank": np.nanmean(der),
        "choice_flip_rate": flips.mean(),
        "rubric_mean_d_exposure": dref.mean(),
        "rubric_flip_rate": rflips.mean(),
        "b1_mean_d_exposure": (hi.b1_exp - lo.b1_exp).mean(),
    }
    for o in DISPOSITIONS:
        row[f"mean_d_p_{o}"] = (hi[f"p_{o}"] - lo[f"p_{o}"]).mean()
    rows.append(row)
CFT = pd.DataFrame(rows)
for dom in ("sca", "sast"):
    m = CFT.domain == dom
    CFT.loc[m, "jev_rank_by_d_noul"] = CFT[m].mean_d_noul.rank(ascending=False)
    CFT.loc[m, "jev_rank_by_d_score"] = CFT[m].mean_d_score.rank(ascending=False)
    CFT.loc[m, "rubric_rank_by_d_exposure"] = CFT[m].rubric_mean_d_exposure.rank(ascending=False)
table(CFT, "counterfactual_attribute_effects")
pd.DataFrame(per_pair).to_csv(TAB / "counterfactual_pairs.csv", index=False)
OUT["counterfactual"] = CFT.to_dict("records")
from scipy.stats import spearmanr  # noqa: E402

OUT["counterfactual_rank_agreement"] = {
    dom: {
        "spearman_jev_d_score_vs_rubric_d_exposure": float(
            spearmanr(
                CFT[CFT.domain == dom].mean_d_score, CFT[CFT.domain == dom].rubric_mean_d_exposure
            ).statistic
        ),
        "spearman_jev_d_noul_vs_rubric_d_exposure": float(
            spearmanr(
                CFT[CFT.domain == dom].mean_d_noul, CFT[CFT.domain == dom].rubric_mean_d_exposure
            ).statistic
        ),
    }
    for dom in ("sca", "sast")
}

# ---------------------------------------------------------------------------
# 6. Adversarial text
# ---------------------------------------------------------------------------
AD = J[J.experiment == "adversarial"]
base = AD[AD.variant == "normal"].set_index("group")
rows = []
for _, x in AD[AD.variant != "normal"].iterrows():
    a = base.loc[x.group]
    rows.append(
        {
            "domain": x.domain,
            "variant": x.variant,
            "group": x.group,
            "base_ref_urgent": a.ref_urgent,
            "flip": x.choice != a.choice,
            "choice_normal": a.choice,
            "choice_adv": x.choice,
            "d_noul": x.noul - a.noul,
            "d_score": x.score - a.score,
            "d_p_DEFER": x.p_DEFER - a.p_DEFER,
            "d_p_EMERGENCY": x.p_EMERGENCY - a.p_EMERGENCY,
            "d_conf": x.choice_confidence - a.choice_confidence,
            "material": abs(x.noul - a.noul) >= 0.10 or abs(x.score - a.score) >= 0.5,
        }
    )
ADD = pd.DataFrame(rows)
ADD.to_csv(TAB / "adversarial_pairs.csv", index=False)
adagg = (
    ADD.groupby(["domain", "variant"])
    .agg(
        n=("group", "size"),
        flip_rate=("flip", "mean"),
        material_change_rate=("material", "mean"),
        mean_d_noul=("d_noul", "mean"),
        mean_abs_d_noul=("d_noul", lambda s: s.abs().mean()),
        mean_d_score=("d_score", "mean"),
        mean_d_p_DEFER=("d_p_DEFER", "mean"),
        mean_d_p_EMERGENCY=("d_p_EMERGENCY", "mean"),
        mean_d_conf=("d_conf", "mean"),
    )
    .reset_index()
)
table(adagg, "adversarial_summary")
OUT["adversarial"] = {
    "by_domain_variant": adagg.to_dict("records"),
    "by_variant": ADD.groupby("variant")[["flip", "material", "d_noul", "d_score"]].mean().to_dict("index"),
    "overall_flip_rate": float(ADD.flip.mean()),
    "overall_material_rate": float(ADD.material.mean()),
    "max_abs_d_noul": float(ADD.d_noul.abs().max()),
    "max_abs_d_score": float(ADD.d_score.abs().max()),
}

# ---------------------------------------------------------------------------
# 7. Representation stability and repeat determinism
# ---------------------------------------------------------------------------
PA = J[J.experiment == "paraphrase"]
canon = PA[PA.variant == "canonical"].set_index("group")
rows = []
for _, x in PA[PA.variant != "canonical"].iterrows():
    a = canon.loc[x.group]
    rows.append(
        {
            "domain": x.domain,
            "variant": x.variant,
            "group": x.group,
            "same_choice": x.choice == a.choice,
            "d_noul": x.noul - a.noul,
            "d_score": x.score - a.score,
            "correct_canonical": a.choice == a.ref_disp,
            "correct_variant": x.choice == x.ref_disp,
        }
    )
PAD = pd.DataFrame(rows)
PAD.to_csv(TAB / "paraphrase_pairs.csv", index=False)
paagg = (
    PAD.groupby(["domain", "variant"])
    .agg(
        n=("group", "size"),
        agreement=("same_choice", "mean"),
        mean_abs_d_noul=("d_noul", lambda s: s.abs().mean()),
        max_abs_d_noul=("d_noul", lambda s: s.abs().max()),
        mean_abs_d_score=("d_score", lambda s: s.abs().mean()),
        acc_canonical=("correct_canonical", "mean"),
        acc_variant=("correct_variant", "mean"),
    )
    .reset_index()
)
table(paagg, "paraphrase_summary")
OUT["paraphrase"] = {
    "by_domain_variant": paagg.to_dict("records"),
    "overall_agreement": float(PAD.same_choice.mean()),
    "all_four_agree_groups": int(PA.groupby("group").choice.nunique().eq(1).sum()),
    "n_groups": int(PA.group.nunique()),
}

RP = J[J.experiment == "repeat"]
rows = []
for gid, g in RP.groupby("group"):
    pcols = [f"p_{o}" for o in DISPOSITIONS] + [f"s_{i}" for i in range(5)]
    rows.append(
        {
            "group": gid,
            "domain": g.domain.iloc[0],
            "n": len(g),
            "distinct_choices": g.choice.nunique(),
            "noul_range": g.noul.max() - g.noul.min(),
            "score_range": g.score.max() - g.score.min(),
            "max_prob_range": float((g[pcols].max() - g[pcols].min()).max()),
            "distinct_response_ids": g.response_id.nunique(),
        }
    )
RPT = pd.DataFrame(rows)
table(RPT, "repeat_determinism")
OUT["repeat"] = {
    "n_groups": int(len(RPT)),
    "requests_per_group": 4,
    "groups_with_identical_choice": int((RPT.distinct_choices == 1).sum()),
    "max_noul_range": float(RPT.noul_range.max()),
    "max_score_range": float(RPT.score_range.max()),
    "max_any_probability_range": float(RPT.max_prob_range.max()),
    "mean_noul_range": float(RPT.noul_range.mean()),
}

# ---------------------------------------------------------------------------
# 8. Calibration (Noul vs rubric urgency) on every distinct determinate request
# ---------------------------------------------------------------------------
U = J[J.ref_urgent.notna()].drop_duplicates("request_key")
U = U[~U.request_key.str.contains("-rep")]
OUT["calibration_all_determinate"] = {
    "note": "distinct requests with a determinate urgency reference across all "
    "experiments; cases are correlated (shared contexts), so treat as descriptive",
    **A.urgency_metrics(U.ref_urgent, U.noul),
}

# ---------------------------------------------------------------------------
# 9. Where Jev and the rubric disagree most (primary set)
# ---------------------------------------------------------------------------
P2 = P.copy()
P2["rank_gap"] = P2.rank_pred - P2.rank_ref
dis = P2[P2.choice != P2.ref_disp].sort_values("rank_gap")
table(
    dis[
        [
            "case_id",
            "domain",
            "experiment",
            "ref_disp",
            "ref_exp",
            "choice",
            "choice_confidence",
            "noul",
            "score",
            "b0_disp",
            "b1_disp",
            "rank_gap",
        ]
    ],
    "primary_disagreements",
)
OUT["disagreement_direction"] = {
    dom: {
        "n_disagree": int(len(g)),
        "jev_lower_priority": int((g.rank_gap < 0).sum()),
        "jev_higher_priority": int((g.rank_gap > 0).sum()),
        "jev_review": int(g.choice.eq("REVIEW").sum()),
    }
    for dom, g in dis.groupby("domain")
}

(ROOT / "results/analysis").mkdir(parents=True, exist_ok=True)
(ROOT / "results/analysis/metrics.json").write_text(json.dumps(r(OUT), indent=1, default=str) + "\n")
print(
    f"analysis complete: {len(J)} answered cases, {OUT['run']['requests_ok']} ok requests, "
    f"frozen artifacts unchanged={not changed}"
)
