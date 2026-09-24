"""Scan every file that git would publish for credentials.

Checks: the literal value of any variable in .env (when present locally), OpenRouter key patterns,
bearer tokens, Authorization headers with values, and common cloud/API key shapes. .gz files are
decompressed; screenshot byte recordings (.cast) are scanned too (PNG pixels cannot be grepped, but
each PNG is rendered only from its scanned .cast recording). Exit code 1 on any hit.
"""

import re
import subprocess
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "openrouter_key": re.compile(rb"sk-or-v\d-[A-Za-z0-9]{20,}"),
    "generic_sk_key": re.compile(rb"\bsk-[A-Za-z0-9_\-]{32,}"),
    "bearer_token": re.compile(rb"(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}"),
    "authorization_header": re.compile(
        rb"(?i)[\"']?authorization[\"']?\s*[:=]\s*[\"']?(bearer|basic|token)\s+[A-Za-z0-9]"
    ),
    "aws_access_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
    "private_key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}
ALLOW = {"scripts/secret_scan.py", "tests/test_design.py"}  # contain patterns / fake test keys by design


def literal_values() -> list[bytes]:
    vals = []
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                v = line.split("=", 1)[1].strip().strip('"').strip("'")
                if len(v) >= 12:
                    vals.append(v.encode())
    return vals


files = subprocess.run(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
    cwd=ROOT,
    capture_output=True,
    text=True,
    check=True,
).stdout.split()
lits = literal_values()
hits = []
scanned = 0
for f in files:
    p = ROOT / f
    if not p.is_file():
        continue
    data = p.read_bytes()
    if f.endswith(".gz"):
        data = zlib.decompressobj(31).decompress(data)  # tolerant of a shard still being written
    scanned += 1
    for v in lits:
        if v in data:
            hits.append((f, "LITERAL .env VALUE"))
    if f in ALLOW:
        continue
    for name, pat in PATTERNS.items():
        if pat.search(data):
            hits.append((f, name))
tracked_env = [
    f for f in files if Path(f).name == ".env" or (Path(f).name.startswith(".env.") and f != ".env.example")
]
print(f"scanned {scanned} publishable files ({'with' if lits else 'without'} literal .env value check)")
print(f".env files that would be published: {tracked_env or 'none'}")
if hits or tracked_env:
    for h in hits:
        print("  HIT", h)
    sys.exit(1)
print("SECRET SCAN PASSED: no credentials found")
