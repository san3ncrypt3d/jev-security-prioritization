"""Show the Jev/OpenRouter configuration with the credential redacted."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jev_security import client  # noqa: E402

key = None
try:
    key = client.load_api_key(ROOT / ".env")
    key_status = "set, value redacted"
except RuntimeError:
    key_status = "NOT SET"
del key
print("OpenRouter Decisions API configuration")
print("-" * 40)
print(f"endpoint          : {client.ENDPOINT}")
print(f"model (pinned)    : {client.MODEL}")
print(f"credential env var: {client.ENV_VAR} = <{key_status}>")
print(f"timeout           : {client.TIMEOUT_S}s")
print(
    f"max attempts      : {client.MAX_ATTEMPTS} (retry only on {sorted(client.RETRY_STATUSES)} / network errors)"
)
print(f".env tracked by git: {'no' if '.env' in (ROOT / '.gitignore').read_text().split() else 'YES (!)'}")
