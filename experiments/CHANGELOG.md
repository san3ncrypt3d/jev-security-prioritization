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
