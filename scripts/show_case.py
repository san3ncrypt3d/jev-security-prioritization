"""Print the exact Jev state for a case, plus (separately) its local reference/baseline labels."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
cid = sys.argv[1]
d = "sca" if cid.startswith("sca") else "sast"
c = next(c for c in json.loads((ROOT / f"data/{d}_cases.json").read_text())["cases"] if c["case_id"] == cid)
print(f"# state sent to Jev for {cid} (experiment={c['experiment']})")
print(json.dumps(c["state"], indent=1, ensure_ascii=False) if not isinstance(c["state"], str) else c["state"])
if "--labels" in sys.argv:
    r = c["reference"]
    print("\n# local labels (never sent to Jev)")
    print(f"reference rubric : {r['disposition']:<11} exposure={r['exposure']} urgent={r['urgent']}")
    for k, v in c["baselines"].items():
        print(f"baseline {k:<15}: {v['disposition']:<11} exposure={v['exposure']} urgent={v['urgent']}")
