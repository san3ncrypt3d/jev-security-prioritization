"""Hashing and environment provenance."""

from __future__ import annotations

import hashlib
import importlib.metadata as md
import json
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

PACKAGES = ["numpy", "pandas", "matplotlib", "scipy", "requests", "rich", "pytest", "ruff"]

# Artifacts frozen before the benchmark; hashes live in experiments/hashes.json.
FROZEN_ARTIFACTS = [
    "experiments/experiment_manifest.json",
    "experiments/question_definitions.json",
    "data/sca_cases.json",
    "data/sast_cases.json",
    "data/reference_labels.json",
    "data/smoke_case.json",
    "src/jev_security/questions.py",
    "src/jev_security/baseline.py",
    "src/jev_security/reference.py",
    "src/jev_security/render.py",
    "src/jev_security/schemas.py",
    "src/jev_security/datasets.py",
]


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def git_dirty() -> bool | None:
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True, timeout=10
        )
        return bool(out.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return None


def software_versions() -> dict:
    v = {"python": sys.version.split()[0], "platform": platform.platform()}
    for p in PACKAGES:
        try:
            v[p] = md.version(p)
        except md.PackageNotFoundError:
            v[p] = None
    return v


def load_hashes() -> dict:
    return json.loads((ROOT / "experiments/hashes.json").read_text())


def verify_frozen() -> list[str]:
    """Return a list of frozen artifacts whose current hash differs from hashes.json."""
    recorded = load_hashes()["sha256"]
    return [p for p, h in recorded.items() if sha256_file(ROOT / p) != h]
