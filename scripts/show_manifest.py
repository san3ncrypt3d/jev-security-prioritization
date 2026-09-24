"""Compact view of the frozen experiment manifest."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
m = json.loads((ROOT / "experiments/experiment_manifest.json").read_text())
print(f"experiment        : {m['experiment']} v{m['experiment_version']}")
print(f"model requested   : {m['model_requested']}")
print(f"endpoint          : {m['endpoint']}")
print(f"random seed       : {m['random_seed']}")
print(
    f"python / numpy    : {m['software_versions_at_freeze']['python']} / {m['software_versions_at_freeze']['numpy']}"
)
print("hypotheses:")
for k, v in m["hypotheses"].items():
    print(f"  {k}: {v[:96]}{'…' if len(v) > 96 else ''}")
print(f"thresholds        : {json.dumps(m['thresholds'])}")
print(
    f"planned requests  : {m['execution']['planned_unique_requests']} (+1 smoke), cost gate ${m['execution']['cost_gate_usd']}"
)
