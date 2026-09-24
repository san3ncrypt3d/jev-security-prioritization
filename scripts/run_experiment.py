"""Run one experiment phase (GATE 5: sca_main, GATE 6: sast_main, GATE 7: secondary).

python scripts/run_experiment.py --phase sca_main --run-id run-v1.0.0
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jev_security.experiment import PHASE_ORDER, run_phase  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--phase", choices=PHASE_ORDER, required=True)
ap.add_argument("--run-id", default="run-v1.0.0")
ap.add_argument("--limit", type=int, default=None)
args = ap.parse_args()
stats = run_phase(args.phase, args.run_id, limit=args.limit)
print(json.dumps({"phase": args.phase, **stats}, indent=1))
