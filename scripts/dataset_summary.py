"""Summarize frozen datasets: cases, unique requests and reference-label distribution."""

import collections
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORDER = [
    "main",
    "contradiction",
    "inconsistent",
    "missing",
    "counterfactual",
    "adversarial",
    "paraphrase",
    "repeat",
]
DISP = ["DEFER", "STANDARD", "ACCELERATED", "EMERGENCY", "REVIEW"]
for d in ("sca", "sast"):
    cases = json.loads((ROOT / f"data/{d}_cases.json").read_text())["cases"]
    print(
        f"{d.upper()}  ({len(cases)} cases, {len({c['request_key'] for c in cases})} unique request payloads)"
    )
    print(f"  {'experiment':<15}{'cases':>6}  " + "".join(f"{x[:5]:>7}" for x in DISP))
    for e in ORDER:
        sub = [c for c in cases if c["experiment"] == e]
        cnt = collections.Counter(c["reference"]["disposition"] for c in sub)
        print(f"  {e:<15}{len(sub):>6}  " + "".join(f"{cnt.get(x, 0):>7}" for x in DISP))
    print()
m = json.loads((ROOT / "experiments/experiment_manifest.json").read_text())
print(
    f"planned unique API requests (all phases): {m['execution']['planned_unique_requests']} "
    f"{m['execution']['planned_by_phase']}"
)
