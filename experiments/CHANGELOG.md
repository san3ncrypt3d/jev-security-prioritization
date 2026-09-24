# Experiment changelog

## v1.0.0 (frozen 2026-09-24 UTC, commit 112fb84)
Pre-registered benchmark: datasets, rubric, baselines, questions, manifest. Hashes in
`experiments/hashes.json`. Executed as run `run-v1.0.0` (878 requests + 1 smoke test). No v1.0
artifact was modified after freezing (verified before every phase and in the analysis).

Pre-freeze design changes (made before ANY Jev call, recorded for transparency):
- Counterfactual contexts stratified by reference exposure (3 per level) instead of uniform random,
  because uniform contexts were mostly low-exposure.
- Rubric: SAST `test_code` (not deployed) gets impact 0 (a unit test exposed the gap).

## v1.1.0-scale-addendum
Added after v1.0 completed, at the user's request, to show throughput and cost at scale:
50,000 new synthetic findings (25k SCA + 25k SAST, uniform sampling, new seed), same frozen
questions/rubric/baselines/renderer, 8 concurrent workers, hard budget stop $3.50. The user approved
the ~$2.60 estimate, which exceeded the original $1 gate. Manifest: `experiments/v1.1_scale_manifest.json`.
This addendum does not change any v1.0 number.

## v1.2.0-frontier-addendum
Added at the user's request to compare decision latency, run time and cost with frontier chat
models (anthropic/claude-sonnet-5, openai/gpt-6-sol, google/gemini-3.8-flash) on 40 stratified
v1.0 main cases, with Jev re-run on the same cases in the same time window. Same states and
verbatim question definitions, sent as a JSON-answer prompt through OpenRouter chat completions
(reasoning effort minimal). The user chose this option (est. $0.80; hard stop $1.20). Accuracy on
40 cases is descriptive only. Manifest: `experiments/v1.2_frontier_manifest.json`.

## v1.2.1-frontier-addendum (bug fix, before any frontier result was observed)
The v1.2.0 run crashed on its first call: the Jev record's `effort` label was "n/a", and the "/"
made the raw-record filename an invalid path. That one Jev request (case sca-main-085) was sent
and billed (~$0.00005), but its response was lost before it could be saved, so it was never
observed. One frontier request (google/gemini-3.8-flash on the same case, first in that case's
shuffled order) completed and was saved normally before the crash; it is kept and not re-sent. Fix: the label is now "none". v1.2.0's manifest is
kept unchanged; v1.2.1's manifest covers the fixed files. The crash is preserved in
`screenshots/recordings/08_final__frontier_v1.2.0_crash.cast`.

## v2.0.0 (raw-evidence field extraction)
Prompted by a reader question: if the facts are already verified, a rule decides; so where does Jev
help? v2 gives only raw evidence (file path, code snippet, route registration, deployment config)
for 450 synthetic SAST findings and asks Jev, a regex baseline and Claude Sonnet 5 (150-finding
subset) to produce the facts; all feed the same frozen v1 rule. The regex and the Jev questions were
committed (git f309979) before the held-out set B was written. A screenshot render failed after the
run completed (missing output folder); the recording was intact and rendered afterwards. No request
was re-run. Manifest: `experiments/v2_manifest.json`.
