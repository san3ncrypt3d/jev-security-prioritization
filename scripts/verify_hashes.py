"""Verify frozen artifacts against experiments/hashes.json."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jev_security.provenance import load_hashes, sha256_file  # noqa: E402

h = load_hashes()
print(f"experiment_version={h['experiment_version']} model={h['model_requested']} seed={h['random_seed']}")
bad = 0
for p, want in h["sha256"].items():
    ok = sha256_file(ROOT / p) == want
    bad += not ok
    print(f"  {'OK  ' if ok else 'DIFF'} {want[:16]}…  {p}")
print(f"manifest sha256: {sha256_file(ROOT / 'experiments/experiment_manifest.json')}")
v11 = ROOT / "experiments/v1.1_scale_manifest.json"
if v11.exists():
    import json

    print("v1.1 scale addendum:")
    for p, want in json.loads(v11.read_text())["sha256"].items():
        ok = sha256_file(ROOT / p) == want
        bad += not ok
        print(f"  {'OK  ' if ok else 'DIFF'} {want[:16]}…  {p}")
print("ALL FROZEN ARTIFACTS MATCH" if not bad else f"{bad} ARTIFACT(S) CHANGED")
sys.exit(1 if bad else 0)
