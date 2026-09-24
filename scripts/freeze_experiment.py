"""Generate datasets, reference labels, question definitions and the frozen
experiment manifest, then hash everything into experiments/hashes.json.

Refuses to run if a manifest already exists (post-freeze changes require a
new experiment version, documented in experiments/CHANGELOG.md).
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jev_security import __version__  # noqa: E402
from jev_security import baseline as B  # noqa: E402
from jev_security import datasets as D  # noqa: E402
from jev_security.client import ENDPOINT, MAX_ATTEMPTS, MODEL, RETRY_STATUSES, TIMEOUT_S  # noqa: E402
from jev_security.experiment import INTER_REQUEST_DELAY_S, PHASE_ORDER, PHASES, plan_requests  # noqa: E402
from jev_security.provenance import FROZEN_ARTIFACTS, sha256_file, software_versions  # noqa: E402
from jev_security.questions import QUESTIONS  # noqa: E402
from jev_security.render import ADVERSARIAL_TEXT  # noqa: E402
from jev_security.schemas import SAST_DOMAINS, SCA_DOMAINS  # noqa: E402

MANIFEST = ROOT / "experiments/experiment_manifest.json"


def dump(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1, ensure_ascii=False) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="only for building a NEW experiment version")
    args = ap.parse_args()
    if MANIFEST.exists() and not args.force:
        raise SystemExit("Manifest already frozen. Bump the experiment version and document why.")

    summary = {}
    all_ref = {}
    for d in ("sca", "sast"):
        cases = D.build_domain(d)
        dump(
            ROOT / f"data/{d}_cases.json",
            {
                "domain": d,
                "experiment_version": __version__,
                "seed": D.SEED,
                "n_cases": len(cases),
                "cases": cases,
            },
        )
        all_ref.update(
            {c["case_id"]: {"domain": d, "experiment": c["experiment"], **c["reference"]} for c in cases}
        )
        summary[d] = {
            "n_cases": len(cases),
            "n_unique_requests": len({c["request_key"] for c in cases}),
            "by_experiment": dict(collections.Counter(c["experiment"] for c in cases)),
            "reference_disposition_by_experiment": {
                e: dict(
                    collections.Counter(c["reference"]["disposition"] for c in cases if c["experiment"] == e)
                )
                for e in sorted({c["experiment"] for c in cases})
            },
        }
    dump(
        ROOT / "data/reference_labels.json",
        {
            "note": "Reference-rubric labels, computed before any Jev call. Not ground truth.",
            "labels": all_ref,
        },
    )
    dump(ROOT / "data/smoke_case.json", D.smoke_case())
    dump(ROOT / "experiments/question_definitions.json", {"model": MODEL, "questions": QUESTIONS})

    plan = plan_requests()
    manifest = {
        "experiment": "jev-security-prioritization",
        "experiment_version": __version__,
        "frozen_note": "Created before the main Jev run. Any later change requires a new version.",
        "model_requested": MODEL,
        "endpoint": ENDPOINT,
        "random_seed": D.SEED,
        "software_versions_at_freeze": software_versions(),
        "research_question": (
            "Can a structured decision model prioritize cybersecurity findings using contextual "
            "evidence that traditional severity scores do not fully capture?"
        ),
        "hypotheses": {
            "H1": "On determinate main+contradiction cases, Jev's Choice disposition agrees with the "
            "reference rubric more often than the severity-only baseline (B0), in each domain.",
            "H2": "Jev's Noul urgency probability discriminates rubric-urgent from rubric-non-urgent "
            "cases (ROC AUC > 0.5 with bootstrap 95% CI excluding 0.5).",
            "H3": "In matched counterfactual pairs, switching an attribute to its riskier value raises "
            "Jev's urgency probability and expected exposure score on average; the ranking of "
            "attribute effects is compared (not assumed equal) to the rubric's.",
            "H4": "When a decision-relevant field is unknown, omitted or contradictory, Jev assigns more "
            "probability to REVIEW and/or lower Choice confidence than for the matched known case.",
            "H5 (null)": "Untrusted instruction-like or argumentative text in the description does not "
            "change Jev's disposition when all structured attributes are identical.",
            "H6": "Semantically equivalent representations of a case produce the same disposition.",
            "H7 (exploratory)": "Agreement and sensitivity patterns differ between SCA and SAST.",
            "H8 (exploratory)": "Noul urgency probabilities are calibrated against rubric urgency "
            "(Brier score, reliability curve, ECE).",
        },
        "datasets": {
            "files": [
                "data/sca_cases.json",
                "data/sast_cases.json",
                "data/reference_labels.json",
                "data/smoke_case.json",
            ],
            "nature": "Fully synthetic. Synthetic package names, service names, advisory and finding IDs. "
            "No real CVE identifiers are used (avoids model prior knowledge of specific CVEs and "
            "any proprietary data).",
            "summary": summary,
        },
        "case_generation_rules": {
            "sampler": "Each attribute drawn uniformly from its domain (seeded Python random); for SCA a "
            "KEV-listed case with exploit 'none' is set to 'weaponized' for consistency.",
            "main": f"Stratified rejection sampling: {D.N_MAIN_PER_LEVEL} cases per reference exposure "
            "level 0-4 (100 per domain).",
            "contradiction": f"{D.N_CONTRADICTION_EACH} 'high severity / low context' + "
            f"{D.N_CONTRADICTION_EACH} 'lower severity / high context' per domain; rule "
            "definitions in datasets._hs_lc_ok/_ls_hc_ok.",
            "inconsistent": f"{D.N_INCONSISTENT} per domain; one field replaced by two disagreeing "
            "evidence sources; only conflicts that change the rubric outcome are kept.",
            "missing": f"{D.N_MISSING_BASES} random main cases per domain; each of fields "
            f"SCA={D.SCA_MISSING_FIELDS} / SAST={D.SAST_MISSING_FIELDS} set to 'unknown' or "
            "omitted, one at a time.",
            "counterfactual": f"{D.N_CF_CONTEXTS} random contexts per domain (3 per reference exposure "
            "level); for each attribute toggle both the low and high value are rendered "
            "with everything else constant.",
            "counterfactual_toggles": {"sca": D.SCA_TOGGLES, "sast": D.SAST_TOGGLES},
            "adversarial": f"{D.N_ADV_BASES} main cases per domain (5 rubric-urgent, 5 not); description "
            "suffixes are listed below; structured attributes identical.",
            "adversarial_text": ADVERSARIAL_TEXT,
            "paraphrase": f"{D.N_PARA_BASES} random main cases per domain rendered as canonical, reworded "
            "description, alternative key names/encodings/order, and prose string.",
            "repeat": f"{D.N_REPEAT_BASES} random main cases per domain re-sent {D.N_REPEATS} additional "
            "times with byte-identical payloads.",
            "state_hygiene": "Only facts are rendered into state. Case IDs, experiment names, variants and "
            "reference labels never appear in state.",
        },
        "attributes": {
            "sca": {k: [str(x) for x in v] for k, v in SCA_DOMAINS.items()},
            "sast": {k: [str(x) for x in v] for k, v in SAST_DOMAINS.items()},
            "mechanical_fields_computed_in_code": [
                "cvss_severity (FIRST v3 bands)",
                "epss_band (very low <0.01, low <0.1, elevated <0.5, high >=0.5)",
            ],
            "context_only_fields_ignored_by_rubric": {
                "sca": ["attack_complexity", "fix_available", "dependency_type", "description"],
                "sast": ["cwe/category", "source/sink/code_flow text", "description"],
            },
        },
        "reference_rubric": {
            "status": "Experimental rubric written before any Jev output; NOT universal ground truth.",
            "implementation": "src/jev_security/reference.py",
            "labels_file": "data/reference_labels.json",
            "summary": "THREAT(0-3) x IMPACT(0-3) -> EXPOSURE(0-4); DEFER/STANDARD/STANDARD/ACCELERATED/"
            "EMERGENCY; urgent = exposure>=3. Unknown/omitted/conflicting fields: rubric "
            "evaluated for all completions; disagreement -> REVIEW (and no determinate "
            "exposure/urgency reference).",
        },
        "jev_questions": {
            "definitions_file": "experiments/question_definitions.json",
            "one_request_per_case": "urgent (noul), disposition (choice), exposure (score) in one request.",
            "questions": QUESTIONS,
        },
        "baselines": {
            "implementation": "src/jev_security/baseline.py",
            "B0_severity_only": B.SEVERITY_TO_DISPOSITION,
            "B0_exposure": B.SEVERITY_TO_EXPOSURE,
            "B1_context_points": {
                "severity_points": B.SEV_POINTS,
                "sca": "+3 KEV; +2 EPSS>=0.5 / +1 EPSS>=0.1; +1 internet; +2 reachable (+1 unknown)",
                "sast": "+3 attacker-controlled (+1 unknown); +2 reachable (+1 unknown); +1 internet; "
                "+2 no sanitization / +1 partial or unknown; +1 no authentication",
                "both": "+asset points "
                + json.dumps(B.ASSET_POINTS)
                + "; -control penalty "
                + json.dumps(B.CONTROL_PENALTY),
                "disposition_thresholds": B.B1_DISPOSITION_THRESHOLDS,
                "exposure_thresholds": B.B1_EXPOSURE_THRESHOLDS,
                "urgent_threshold": B.B1_URGENT_THRESHOLD,
            },
            "caveat": "The rubric and B1 were written by the same author and share signals, so B1-rubric "
            "agreement is not an independent validity measure.",
        },
        "thresholds": {
            "noul_urgent": 0.5,
            "material_noul_change": 0.10,
            "material_score_change": 0.5,
            "choice_flip": "selected option differs",
        },
        "metrics": [
            "Choice accuracy vs rubric (overall, per domain, per experiment) with bootstrap 95% CI",
            "Macro-F1 and confusion matrix (5 dispositions)",
            "False escalation rate: predicted priority rank > reference rank (determinate cases)",
            "False deprioritization rate: predicted priority rank < reference rank",
            "REVIEW precision/recall",
            "Noul ROC AUC, precision/recall/F1 at 0.5, Brier score, ECE (10 equal-width bins), "
            "reliability curve",
            "Score MAE and Spearman rho vs rubric exposure; quadratic-weighted kappa of rounded score",
            "Same metrics for B0 and B1",
            "Exact McNemar test Jev vs each baseline on Choice correctness (paired)",
            "Counterfactual deltas: mean delta noul, delta expected score, delta P(option), flip rate, "
            "per attribute, with bootstrap CI over contexts; compared to rubric deltas",
            "Missing/inconsistent: delta P(REVIEW), delta Choice confidence, REVIEW selection rate, "
            "delta noul vs known anchor",
            "Adversarial: flip rate, delta noul, delta score, delta P(DEFER)/P(EMERGENCY) vs normal anchor",
            "Paraphrase: disposition agreement with canonical, SD of noul and score across variants",
            "Repeat: max |delta| across byte-identical requests",
            "Latency (client-side), input/output tokens, cost (usage.cost)",
        ],
        "planned_analyses": [
            "Primary: main+contradiction per domain (H1, H2).",
            "Severity-vs-context: contradiction subset, direction of Jev's move relative to B0.",
            "Counterfactual attribute sensitivity (H3).",
            "Missing and inconsistent evidence (H4), also split by stakes: REVIEW references where the uncertainty changes urgency (urgent reference undetermined) vs. only the DEFER/STANDARD boundary.",
            "Adversarial text (H5).",
            "Representation stability and repeat determinism (H6).",
            "SCA vs SAST comparison (H7).",
            "Calibration where n supports it (H8); ECE reported with the bin counts.",
        ],
        "exclusion_criteria": [
            "Requests that fail after the bounded retry policy are reported with their error and excluded "
            "from metric denominators; failure counts are always reported.",
            "Successful responses missing any of the three answers are treated as failures.",
            "No case is excluded for any other reason. Surprising successful responses are never re-run.",
            "Noul/Score metrics use only cases with a determinate rubric reference (REVIEW-reference cases "
            "have no urgency/exposure reference by construction).",
        ],
        "execution": {
            "phases": {k: [v[0], sorted(v[1])] for k, v in PHASES.items()},
            "phase_order": PHASE_ORDER,
            "planned_unique_requests": len(plan),
            "planned_by_phase": dict(collections.Counter(p["phase"] for p in plan)),
            "smoke_test_requests": 1,
            "request_policy": {
                "timeout_s": TIMEOUT_S,
                "max_attempts": MAX_ATTEMPTS,
                "retry_statuses": sorted(RETRY_STATUSES),
                "inter_request_delay_s": INTER_REQUEST_DELAY_S,
                "concurrency": 1,
            },
            "cost_gate_usd": 1.0,
            "bootstrap": {"resamples": 2000, "seed": D.SEED},
        },
    }
    dump(MANIFEST, manifest)

    hashes = {
        "experiment_version": __version__,
        "model_requested": MODEL,
        "endpoint": ENDPOINT,
        "random_seed": D.SEED,
        "sha256": {p: sha256_file(ROOT / p) for p in FROZEN_ARTIFACTS},
    }
    dump(ROOT / "experiments/hashes.json", hashes)
    print(json.dumps({"planned_unique_requests": len(plan), **summary}, indent=1))


if __name__ == "__main__":
    main()
