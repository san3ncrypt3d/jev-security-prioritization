"""Experiment v1.2 addendum: frontier-model latency/cost comparison (40 cases, 3 models + Jev).

python scripts/frontier_run.py freeze
python scripts/frontier_run.py run
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jev_security import frontier as F  # noqa: E402
from jev_security.provenance import sha256_file, software_versions, verify_frozen  # noqa: E402

MAN = ROOT / "experiments/v1.2.1_frontier_manifest.json"
ap = argparse.ArgumentParser()
ap.add_argument("cmd", choices=["freeze", "run"])
a = ap.parse_args()
FILES = ["src/jev_security/frontier.py", "scripts/frontier_run.py"]

if a.cmd == "freeze":
    if MAN.exists():
        sys.exit("v1.2.1 manifest already frozen")
    MAN.write_text(
        json.dumps(
            {
                "experiment_version": "1.2.1-frontier-addendum",
                "reason": "Added at the user's request after v1.0/v1.1 to compare decision latency, run time "
                "and cost with frontier chat models. The user chose 3 models x 40 cases (est. $0.80).",
                "cases": [c["case_id"] for c in F.pick_cases()],
                "jev": {
                    "model": "typesafe/jev-1.13",
                    "endpoint": "https://openrouter.ai/api/alpha/decisions",
                    "payload": "identical to v1.0 (state + frozen questions)",
                },
                "frontier_models": F.FRONTIER_MODELS,
                "frontier_endpoint": F.CHAT_ENDPOINT,
                "frontier_settings": {
                    "temperature": 0,
                    "max_tokens": F.MAX_TOKENS,
                    "response_format": "json_object",
                    "reasoning_effort": "minimal (fallback 'low' only if HTTP 400)",
                    "system_prompt": F.SYSTEM,
                },
                "ordering": "per case, the 4 models are called back-to-back in a seeded shuffled order; sequential",
                "primary_measures": [
                    "client-side latency per decision",
                    "input/output/reasoning tokens",
                    "billed cost (usage.cost)",
                    "JSON validity",
                ],
                "secondary_measures": [
                    "agreement with the frozen v1.0 rubric on these 40 cases (descriptive, small n)"
                ],
                "budget_stop_usd": F.BUDGET_USD,
                "exclusions": "failed or unparseable responses are reported as such, never re-run",
                "software": software_versions(),
                "sha256": {f: sha256_file(ROOT / f) for f in FILES},
            },
            indent=1,
        )
        + "\n"
    )
    print(f"frozen {MAN.relative_to(ROOT)}")
else:
    if verify_frozen():
        sys.exit("v1.0 frozen artifacts changed")
    m = json.loads(MAN.read_text())
    bad = [f for f, h in m["sha256"].items() if sha256_file(ROOT / f) != h]
    if bad:
        sys.exit(f"v1.2.1 artifacts changed: {bad}")
    print(json.dumps(F.run(), indent=1))
