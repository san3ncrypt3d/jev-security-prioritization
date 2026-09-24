# jev-security-prioritization

[![ci](https://github.com/san3ncrypt3d/jev-security-prioritization/actions/workflows/ci.yml/badge.svg)](https://github.com/san3ncrypt3d/jev-security-prioritization/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A reproducible experiment testing whether a structured decision model, TypeSafe's **Jev**
(`typesafe/jev-1.13` through OpenRouter's Decisions API), can prioritize SCA and SAST findings from
context that severity scores don't capture. Jev is compared against a severity-only baseline and a
simple points formula.

## The problem

A scanner says CRITICAL. It doesn't know that the vulnerable function is never called, or that the
service isn't reachable from the internet. Meanwhile a MEDIUM on the payment API has a public exploit
and nothing in front of it. Teams fix this by combining severity with context, usually by hand. This
project measures how well Jev does that combining step, where it fails, and what it costs.

```console
$ python scripts/report.py primary
== Primary set: main + contradiction cases vs the reference rubric ==
domain            method   n  choice_acc  acc_ci_lo  acc_ci_hi  false_escalation  false_deprioritization  urgency_auc  urgency_recall  score_mae
   sca               jev 112       0.554      0.464      0.643             0.179                   0.241        0.966           0.978      0.630
   sca  b0_severity_only 112       0.250      0.170      0.339             0.527                   0.223          NaN           0.674      1.402
   sca b1_context_points 112       0.527      0.438      0.616             0.339                   0.134          NaN           0.935      0.607
  sast               jev 112       0.491      0.402      0.580             0.054                   0.455        0.929           0.870      0.558
  sast  b0_severity_only 112       0.214      0.143      0.295             0.554                   0.232          NaN           0.587      1.634
  sast b1_context_points 112       0.375      0.295      0.464             0.598                   0.027          NaN           1.000      0.920
```

The full write-up is in [`blog/jev-security-prioritization.md`](blog/jev-security-prioritization.md).

## Results summary

All numbers come from `results/analysis/metrics.json` and `results/analysis/scale_metrics.json`.
The reference is an **experimental rubric** written before any Jev call, not ground truth.

- **Context over severity.** Jev agreed with the rubric on 55% (SCA) and 49% (SAST) of dispositions,
  against 25% and 21% for severity-only sorting (exact McNemar p ≈ 5e-6 and 9e-6). Against a simple
  points formula it was a statistical tie (53% and 38%; p = 0.78 and 0.12).
- **Ranking urgency works.** Noul urgency ROC AUC was 0.97 (SCA) and 0.93 (SAST).
- **All 24 conflict cases moved toward context.** When severity and context pointed opposite ways,
  Jev always moved away from the severity label. Changing CVSS from 5.3 to 9.8 on its own flipped
  0 of 15 dispositions.
- **Reachability is the biggest lever.** It raised P(urgent) by 0.28 to 0.29. KEV listing moved Jev
  much less than the rubric expects (+0.09), and SAST authentication barely moved it at all.
- **Write "unknown", don't omit.** An explicit `"unknown"` sent 50% of cases to REVIEW. The same
  field omitted did so 1 time in 80.
- **Text can steer it.** "SYSTEM INSTRUCTION" injections barely moved anything. A calm "known false
  positive" note changed 17 of 20 decisions, 16 of them to REVIEW.
- **Not calibrated against this rubric.** The Brier score beats the base rate (0.13/0.12 vs 0.24),
  but ECE is 0.14 to 0.20. Use P(urgent) to rank, and set thresholds locally.
- **Cost and speed.** The 879 benchmark calls cost $0.0457, at a median latency of 192 ms. A
  50,000-finding run finished in 21.4 minutes (38 per second, 8 workers) for $2.61.
- **Against frontier models** (40 identical cases): Jev's median was 186 ms, against 2.5 to 5.6 s
  for Claude Sonnet 5, GPT-6 Sol and Gemini 3.8 Flash, which were 14 to 30 times slower and 25 to
  83 times more expensive per decision. Sonnet 5 agreed with the rubric more often (78% vs 55%,
  small n).

## Architecture

```
src/jev_security/
  schemas.py     attribute domains, mechanical fields (CVSS band, EPSS band) computed in code
  render.py      facts -> Jev state (canonical JSON, alternative keys, prose); adversarial suffixes
  reference.py   the experimental reference rubric (THREAT x IMPACT -> exposure -> disposition)
  baseline.py    B0 severity-only and B1 context-points baselines
  questions.py   Noul / Choice / Score question definitions
  datasets.py    seeded case generation for all eight sub-experiments
  client.py      Decisions API client: no secret logging, bounded retries, write-once raw records
  experiment.py  phased, resumable, order-shuffled execution with frozen-hash checks
  analysis.py    normalization + metrics (bootstrap CIs, AUC, Brier, ECE, McNemar, kappa)
  provenance.py  hashing, software versions, git commit
  scale.py       v1.1 addendum: 50k-finding throughput and cost run
  frontier.py    v1.2 addendum: latency/cost comparison with frontier chat models
scripts/         freeze, smoke test, cost estimate, run, analyze, figures, report, secret scan,
                 real-terminal screenshots (term_record.py + tools/screenshot/render.mjs)
data/            frozen synthetic datasets and reference labels
experiments/     frozen manifests, SHA-256 hashes, changelog
results/raw/     every raw API response (never overwritten)
results/         normalized/, analysis/, tables/, figures/
screenshots/     real terminal screenshots + their byte recordings (.cast)
blog/            the article and claim_provenance.json
```

## Experiment design

- **Frozen before execution.** `experiments/experiment_manifest.json` holds the hypotheses,
  datasets, rules, questions, baselines, thresholds, metrics, exclusion criteria, and seed. The
  hashes are in `experiments/hashes.json`, and the runner refuses to start if any frozen file has
  changed. The changes made before freezing, and the v1.1 addendum, are listed in
  `experiments/CHANGELOG.md`.
- **One request per case, three questions:** `urgent` (Noul), `disposition` (Choice: DEFER,
  STANDARD, ACCELERATED, EMERGENCY, REVIEW), and `exposure` (Score: 0 Minimal to 4 Critical).
- **Eight sub-experiments per domain:** main (stratified), severity/context contradiction,
  inconsistent sources, missing evidence (unknown vs omitted), single-attribute counterfactuals,
  adversarial description text, paraphrase/representation, and repeat determinism.
- **Everything is synthetic.** No real CVE IDs and no proprietary data. Labels never appear in the
  state (a test enforces this).

## Installation

```bash
git clone https://github.com/san3ncrypt3d/jev-security-prioritization.git
cd jev-security-prioritization
uv venv .venv && source .venv/bin/activate     # or: python -m venv .venv
uv pip install -e '.[dev]' tabulate            # or: pip install -e '.[dev]' tabulate
```

## OpenRouter configuration

You need an OpenRouter API key only to send **new** requests. Everything else, including every
number and figure, can be recomputed offline from the committed raw responses.

```bash
cp .env.example .env
# edit .env:  export OPENROUTER_API_KEY=<your key>
```

`.env` is git-ignored. The client reads the key from the environment or `.env` and only ever uses
it in the Authorization header. It is never printed, logged, or written to a record.

## Reproduce

Offline (no key needed):

```bash
python scripts/verify_hashes.py      # frozen artifacts unchanged
pytest -q                            # rubric, baselines, label hygiene, client secrecy
python scripts/analyze.py            # metrics.json + tables from results/raw/run-v1.0.0
python scripts/analyze_scale.py      # scale_metrics.json from results/raw/scale-v1.1
python scripts/analyze_frontier.py   # frontier_metrics.json from results/raw/frontier-v1.2
python scripts/make_figures.py       # results/figures/*.png
python scripts/report.py counterfactual   # or: primary|contradiction|missing|adversarial|stability|cost|scale
```

Against the API (about $0.05 for the benchmark):

```bash
python scripts/smoke_test.py                                   # one request, contract checks
python scripts/estimate_cost.py                                # estimate from the smoke test's real usage
python scripts/run_experiment.py --phase sca_main  --run-id my-run
python scripts/run_experiment.py --phase sast_main --run-id my-run
python scripts/run_experiment.py --phase secondary --run-id my-run
python scripts/analyze.py --run-id my-run
python scripts/scale_run.py run                                # optional 50k scale run (~$2.60)
python scripts/frontier_run.py run                             # optional frontier comparison (~$0.36)
```

The smoke test refuses to run twice (its raw record is kept). Runs are resumable, and successful
requests are never re-sent. Screenshots are made with `python scripts/screenshot.py OUT.png "cmd"`,
which runs the command in a real terminal session and needs Node.js (`cd tools/screenshot && npm install`).

## Limitations

- Synthetic findings only. Real scanner output is messier.
- The reference rubric is one author's policy. B1 was written by the same author and shares its
  signals, so its agreement with the rubric is flattered.
- 112 primary cases per domain, and 10 to 15 per cell in the secondary experiments. The confidence
  intervals are wide.
- One model snapshot (`typesafe/jev-1.13-20260917`). Later snapshots may behave differently.
- The counterfactual effects are causal only within this controlled synthetic design.

## Responsible use

This is decision-support research. Don't use Jev output (or these baselines) to close, suppress,
or risk-accept findings without a human, and don't skip KEV deadlines on a model's say-so. The
dataset contains no exploit code or operational payloads. The "adversarial" descriptions are
harmless instruction-like strings used to measure steerability.

## License

MIT
