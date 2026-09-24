"""Print the repository tree (excludes .git, .venv, caches and secret files)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".env", "node_modules"}
COLLAPSE_AT = int(sys.argv[2]) if len(sys.argv) > 2 else 8  # dirs with more files are summarized
MAX_DEPTH = int(sys.argv[1]) if len(sys.argv) > 1 else 3


def walk(d: Path, prefix: str = "", depth: int = 0):
    entries = sorted(
        [p for p in d.iterdir() if p.name not in SKIP and not p.name.endswith(".egg-info")],
        key=lambda p: (p.is_file(), p.name),
    )
    files = [p for p in entries if p.is_file()]
    if len(files) > COLLAPSE_AT:
        exts = sorted({p.suffix or p.name for p in files})
        entries = [p for p in entries if p.is_dir()] + [f"({len(files)} files: {', '.join(exts)})"]
    for i, p in enumerate(entries):
        last = i == len(entries) - 1
        branch = "└── " if last else "├── "
        if isinstance(p, str):
            print(prefix + branch + p)
            continue
        print(prefix + branch + p.name + ("/" if p.is_dir() else ""))
        if p.is_dir() and depth + 1 < MAX_DEPTH:
            walk(p, prefix + ("    " if last else "│   "), depth + 1)


print(ROOT.name + "/")
walk(ROOT)
