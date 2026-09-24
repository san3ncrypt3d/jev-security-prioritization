"""Experiment v1.1 addendum: 50k-finding throughput/cost run.

python scripts/scale_run.py build     # generate data/scale_v1.1.jsonl.gz
python scripts/scale_run.py freeze    # write experiments/v1.1_scale_manifest.json + hashes
python scripts/scale_run.py run [--limit N]
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jev_security import scale  # noqa: E402
from jev_security.client import ENDPOINT, MODEL  # noqa: E402
from jev_security.provenance import sha256_file, software_versions, verify_frozen  # noqa: E402

MAN = ROOT / "experiments/v1.1_scale_manifest.json"
ap = argparse.ArgumentParser()
ap.add_argument("cmd", choices=["build", "freeze", "run"])
ap.add_argument("--limit", type=int)
a = ap.parse_args()

if a.cmd == "build":
    print(f"generated {scale.build()} findings -> {scale.DATA.relative_to(ROOT)}")
elif a.cmd == "freeze":
    if MAN.exists():
        sys.exit("v1.1 manifest already frozen")
    files = ["data/scale_v1.1.jsonl.gz", "src/jev_security/scale.py", "scripts/scale_run.py"]
    MAN.write_text(
        json.dumps(
            {
                "experiment_version": "1.1.0-scale-addendum",
                "reason": "Added after v1.0 completed, at the user's request, to measure throughput and cost on "
                "50,000 findings. v1.0 artifacts are unchanged; see experiments/CHANGELOG.md.",
                "model_requested": MODEL,
                "endpoint": ENDPOINT,
                "seed": scale.SCALE_SEED,
                "n_findings": 2 * scale.N_PER_DOMAIN,
                "sampling": "uniform over attribute domains (not stratified)",
                "reuses_frozen_v1.0": [
                    "sampler (datasets._sca/_sast_random_facts)",
                    "render (canonical)",
                    "reference rubric",
                    "baselines",
                    "question definitions",
                ],
                "concurrency": scale.WORKERS,
                "budget_stop_usd": scale.BUDGET_USD,
                "user_approved_estimate_usd": 2.60,
                "primary_measures": [
                    "wall-clock throughput (requests/s)",
                    "latency distribution under concurrency",
                    "total tokens and cost",
                    "error/429 rate",
                ],
                "secondary_measures": [
                    "agreement with the rubric on a uniform sample",
                    "Noul calibration (Brier, ECE, reliability) with n=50k",
                    "choice/score confidence distributions",
                ],
                "software": software_versions(),
                "sha256": {f: sha256_file(ROOT / f) for f in files},
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
        sys.exit(f"v1.1 artifacts changed: {bad}")
    print(json.dumps(scale.run(limit=a.limit), indent=1))
