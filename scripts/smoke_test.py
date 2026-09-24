"""GATE 3: send ONE synthetic security case to Jev and verify the response contract.

Writes the raw record to results/raw/smoke/responses/ (write-once) and prints a
sanitized view: the exact request body (no headers) and the actual response.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jev_security.client import DecisionsClient, build_payload, load_api_key  # noqa: E402
from jev_security.provenance import verify_frozen  # noqa: E402
from jev_security.questions import QUESTIONS  # noqa: E402

case = json.loads((ROOT / "data/smoke_case.json").read_text())
changed = verify_frozen()
if changed:
    sys.exit(f"frozen artifacts changed: {changed}")

payload = build_payload(case["state"], QUESTIONS["sca"])
raw_dir = ROOT / "results/raw/smoke/responses"
existing = sorted(raw_dir.glob("*.json")) if raw_dir.exists() else []
if existing and "--show" in sys.argv:
    rec = json.loads(existing[-1].read_text())  # display the stored record; no new request
else:
    if existing:
        sys.exit("smoke test already executed; use --show to display the stored raw record")
    rec = DecisionsClient(load_api_key(ROOT / ".env")).decide(
        payload, raw_dir, case["request_key"], meta={"phase": "smoke"}
    )

body = rec.get("response_body") or {}
if "--request" in sys.argv:
    print("REQUEST BODY (headers omitted; Authorization header never stored)")
    print(json.dumps(rec["request_payload"]["state"], indent=1))
    sys.exit(0)

print(f"HTTP {rec['http_status']}  latency={rec['latency_ms']} ms  error={rec['error']}")
print("RESPONSE (actual, unmodified):")
print(json.dumps(body, indent=1))
answers = body.get("answers", {})
checks = {
    "authentication works (HTTP 200)": rec["http_status"] == 200,
    "provider is TypeSafe": body.get("provider") == "TypeSafe",
    "model snapshot returned": str(body.get("model", "")).startswith("typesafe/jev-1.13"),
    "request id returned": bool(body.get("id")),
    "noul answer": answers.get("urgent", {}).get("type") == "noul" and "noul" in answers.get("urgent", {}),
    "choice answer + probabilities": "probabilities" in answers.get("disposition", {}),
    "score answer + probabilities": "probabilities" in answers.get("exposure", {}),
    "usage.input_tokens": "input_tokens" in body.get("usage", {}),
    "usage.cost": "cost" in body.get("usage", {}),
}
print("\nCONTRACT CHECKS")
for k, v in checks.items():
    print(f"  [{'PASS' if v else 'FAIL'}] {k}")
print(
    f"\nREFERENCE (rubric, pre-registered): {case['reference']['disposition']}, "
    f"exposure={case['reference']['exposure']}, urgent={case['reference']['urgent']}"
)
sys.exit(0 if all(checks.values()) else 1)
