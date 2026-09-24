"""Print result sections from results/analysis + results/tables (read-only; no API calls).

python scripts/report.py primary|contradiction|counterfactual|missing|adversarial|stability|cost|scale
"""

import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
T = ROOT / "results/tables"
M = json.loads((ROOT / "results/analysis/metrics.json").read_text())
pd.set_option("display.width", 200, "display.max_columns", 30, "display.max_colwidth", 40)
sec = sys.argv[1]


def show(df, title):
    print(f"\n== {title} ==")
    print(df.to_string(index=False, float_format=lambda v: f"{v:.3f}"))


if sec == "primary":
    df = pd.read_csv(T / "primary_metrics.csv")
    show(
        df[
            [
                "domain",
                "method",
                "n",
                "choice_acc",
                "acc_ci_lo",
                "acc_ci_hi",
                "false_escalation",
                "false_deprioritization",
                "urgency_auc",
                "urgency_recall",
                "score_mae",
            ]
        ],
        "Primary set: main + contradiction cases vs the reference rubric",
    )
    for d in ("sca", "sast"):
        p = M["primary"][d]
        print(
            f"{d}: McNemar Jev vs B0 p={p['mcnemar_jev_vs_b0']['p_value_sci']} | Jev vs B1 "
            f"p={p['mcnemar_jev_vs_b1']['p_value_sci']} | Brier={p['jev']['urgency']['brier']:.3f} "
            f"(base-rate {p['jev']['urgency']['brier_base_rate']:.3f}) ECE={p['jev']['urgency']['ece_10bin']:.3f}"
        )
elif sec == "contradiction":
    df = pd.read_csv(T / "contradiction_cases.csv")
    show(
        df[["case_id", "variant", "b0_disp", "ref_disp", "choice", "noul", "score"]],
        "Severity vs context conflict cases",
    )
elif sec == "counterfactual":
    df = pd.read_csv(T / "counterfactual_attribute_effects.csv").sort_values(
        ["domain", "mean_d_score"], ascending=[True, False]
    )
    show(
        df[
            [
                "domain",
                "attribute",
                "n_pairs",
                "mean_d_noul",
                "d_noul_ci_lo",
                "d_noul_ci_hi",
                "mean_d_score",
                "choice_flip_rate",
                "rubric_mean_d_exposure",
            ]
        ],
        "Counterfactual: one attribute low -> high, everything else fixed",
    )
elif sec == "missing":
    df = pd.read_csv(T / "missing_summary.csv")
    show(
        df[
            [
                "domain",
                "field",
                "mode",
                "n",
                "ref_review_rate",
                "selected_review",
                "mean_d_p_review",
                "mean_d_conf",
                "choice_changed",
            ]
        ],
        "Missing evidence vs the known anchor case",
    )
    o = M["missing"]["overall"]["unknown_vs_omitted"]
    print(
        f"\nREVIEW chosen: 'unknown' {o['unknown']['selected_review']:.0%} vs omitted {o['omitted']['selected_review']:.0%}"
    )
elif sec == "adversarial":
    df = pd.read_csv(T / "adversarial_summary.csv")
    show(
        df[
            [
                "domain",
                "variant",
                "n",
                "flip_rate",
                "material_change_rate",
                "mean_d_noul",
                "mean_d_score",
                "mean_d_p_DEFER",
            ]
        ],
        "Untrusted text in the description (structured fields identical)",
    )
elif sec == "stability":
    df = pd.read_csv(T / "paraphrase_summary.csv")
    show(
        df[["domain", "variant", "n", "agreement", "mean_abs_d_noul", "max_abs_d_noul", "mean_abs_d_score"]],
        "Representation stability vs canonical JSON",
    )
    print("\nRepeat determinism:", json.dumps(M["repeat"]))
elif sec == "cost":
    r = M["run"]
    print(
        json.dumps(
            {
                k: r[k]
                for k in [
                    "requests_total_incl_smoke",
                    "requests_ok",
                    "requests_failed",
                    "model_snapshots",
                    "providers",
                    "input_tokens_total",
                    "output_tokens_total",
                    "input_tokens_mean",
                    "cost_total_usd",
                    "cost_per_1000_requests_usd",
                    "latency_ms",
                ]
            },
            indent=1,
        )
    )
elif sec == "frontier":
    df = pd.read_csv(T / "frontier_comparison.csv")
    df = df[
        [
            "model",
            "n",
            "valid",
            "p50_ms",
            "p90_ms",
            "x_slower_than_jev",
            "in_tok",
            "out_tok",
            "usd_per_decision",
            "usd_per_50k",
            "disp_acc_n40",
            "urgency_auc_n40",
        ]
    ]
    print("\n== Same 40 cases, same questions: Jev vs frontier chat models (accuracy columns: small n) ==")
    print(
        df.to_string(
            index=False,
            formatters={
                "p50_ms": "{:.0f}".format,
                "p90_ms": "{:.0f}".format,
                "x_slower_than_jev": "{:.1f}x".format,
                "in_tok": "{:.0f}".format,
                "out_tok": "{:.0f}".format,
                "usd_per_decision": "${:.6f}".format,
                "usd_per_50k": "${:.2f}".format,
                "disp_acc_n40": "{:.3f}".format,
                "urgency_auc_n40": "{:.3f}".format,
            },
        )
    )
elif sec == "totals":
    S = json.loads((ROOT / "results/analysis/scale_metrics.json").read_text())
    F = json.loads((ROOT / "results/analysis/frontier_metrics.json").read_text())
    r = M["run"]
    jev_f = F["models"]["typesafe/jev-1.13"]
    rows = [
        ("v1.0 benchmark + smoke (Jev)", r["requests_ok"], r["input_tokens_total"], r["cost_total_usd"]),
        ("v1.1 scale run (Jev)", S["n_ok"], S["input_tokens_total"], S["cost_total_usd"]),
        (
            "v1.2 frontier comparison (all 4 models)",
            sum(m["requests"] for m in F["models"].values()),
            None,
            F["total_cost_usd"],
        ),
        ("   of which Jev", jev_f["requests"], None, jev_f["cost_total_usd"]),
    ]
    print(f"{'experiment':<42}{'ok requests':>12}{'input tokens':>15}{'cost USD':>12}")
    for n, q, t, c in rows:
        print(f"{n:<42}{q:>12,}{(f'{t:,}' if t else '-'):>15}{c:>12.4f}")
    tot = r["cost_total_usd"] + S["cost_total_usd"] + F["total_cost_usd"]
    print(f"{'TOTAL (successful, billed responses)':<42}{'':>12}{'':>15}{tot:>12.4f}")
elif sec == "scale":
    S = json.loads((ROOT / "results/analysis/scale_metrics.json").read_text())
    keep = [
        "n_findings_planned",
        "n_ok",
        "n_findings_without_success",
        "errors_by_status",
        "model_snapshots",
        "input_tokens_total",
        "cost_total_usd",
        "cost_per_1000_usd",
        "main_session",
        "latency_ms",
    ]
    print(json.dumps({k: S[k] for k in keep}, indent=1))
    a = S["agreement_uniform_sample"]["all"]
    print(
        f"uniform-sample agreement: Jev {a['jev_choice_acc']:.3f}, B0 {a['b0_acc']:.3f}, B1 {a['b1_acc']:.3f}; "
        f"urgency AUC {a['urgency']['auc']:.3f}, Brier {a['urgency']['brier']:.3f}, ECE {a['urgency']['ece_10bin']:.3f}"
    )
