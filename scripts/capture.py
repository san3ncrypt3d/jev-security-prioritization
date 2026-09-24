"""Run a real command and render its sanitized terminal transcript as a PNG.

    python scripts/capture.py screenshots/02_smoke_test/x.png "python scripts/smoke_test.py" \
        --title "..." [--width 110] [--max-lines 60]

The command's actual stdout/stderr is captured, checked for secrets (the
literal API key value from .env, bearer headers, and OpenRouter key
patterns), saved as a transcript, and rendered. If a secret is detected the
screenshot is NOT written and the script exits non-zero. Nothing is invented:
the PNG shows exactly the captured output (optionally truncated, with the
truncation marked).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from rich.console import Console
from rich.text import Text

ROOT = Path(__file__).resolve().parents[1]
SECRET_PATTERNS = [
    re.compile(r"sk-or-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{12,}"),
    re.compile(r"(?i)authorization:\s*\S+"),
]
CHROME = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")


def _secret_values() -> list[str]:
    vals = []
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if "=" in line:
                v = line.split("=", 1)[1].strip().strip('"').strip("'")
                if len(v) >= 12:
                    vals.append(v)
    return vals


def contains_secret(text: str) -> bool:
    return any(v in text for v in _secret_values()) or any(p.search(text) for p in SECRET_PATTERNS)


def render_png(transcript: str, cmd: str, out: Path, title: str, width: int) -> None:
    console = Console(
        record=True, width=width, force_terminal=True, color_system="truecolor", file=open(os.devnull, "w")
    )
    console.print(Text("$ ", style="bold green") + Text(cmd, style="bold"))
    console.print(Text.from_ansi(transcript.rstrip("\n")))
    svg = console.export_svg(title=title)
    m = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    w, h = float(m.group(1)), float(m.group(2))
    with tempfile.TemporaryDirectory() as td:
        html = Path(td) / "s.html"
        html.write_text(
            "<html><body style='margin:0;background:#ffffff'>"
            f"<div style='width:{w}px;height:{h}px'>{svg}</div></body></html>"
        )
        subprocess.run(
            [
                CHROME,
                "--headless=new",
                "--disable-gpu",
                "--hide-scrollbars",
                "--no-sandbox",
                f"--screenshot={out.resolve()}",
                f"--window-size={int(w)},{int(h)}",
                "--force-device-scale-factor=2",
                "--default-background-color=00000000",
                html.as_uri(),
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("cmd")
    ap.add_argument("--title", default="")
    ap.add_argument("--width", type=int, default=110)
    ap.add_argument("--max-lines", type=int, default=0)
    ap.add_argument("--display-cmd", default=None, help="shorter command text to show (must be equivalent)")
    ap.add_argument("--caption", default="")
    ap.add_argument("--section", default="")
    ap.add_argument("--source", default="")
    args = ap.parse_args()

    env = dict(
        os.environ,
        PATH=f"{ROOT / '.venv/bin'}:{os.environ['PATH']}",
        FORCE_COLOR="1",
        COLUMNS=str(args.width),
        PYTHONPATH=str(ROOT / "src"),
    )
    env.pop("OPENROUTER_API_KEY", None)  # the command itself loads .env only if it needs to
    proc = subprocess.run(
        args.cmd, shell=True, cwd=ROOT, env=env, capture_output=True, text=True, timeout=3600
    )
    output = proc.stdout + (proc.stderr if proc.stderr.strip() else "")
    lines = output.splitlines()
    if args.max_lines and len(lines) > args.max_lines:
        omitted = len(lines) - args.max_lines
        lines = lines[: args.max_lines] + [
            f"... [{omitted} more lines truncated for the screenshot; full transcript saved alongside]"
        ]
    shown = "\n".join(lines)
    display_cmd = args.display_cmd or args.cmd

    if contains_secret(output) or contains_secret(display_cmd):
        print("SECRET DETECTED in output; screenshot not written.", file=sys.stderr)
        sys.exit(2)

    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    tdir = ROOT / "screenshots/transcripts"
    tdir.mkdir(parents=True, exist_ok=True)
    stem = out.relative_to(ROOT / "screenshots").with_suffix("").as_posix().replace("/", "__")
    ansi_re = re.compile(r"\x1b\[[0-9;]*m")
    (tdir / f"{stem}.txt").write_text(f"$ {display_cmd}\n" + ansi_re.sub("", output))
    render_png(shown, display_cmd, out, args.title, args.width)

    # Append to the screenshot log (README is generated from it).
    log = ROOT / "screenshots/screenshots.json"
    entries = json.loads(log.read_text()) if log.exists() else []
    entries = [e for e in entries if e["filename"] != args.out]
    entries.append(
        {
            "filename": args.out,
            "title": args.title,
            "command": display_cmd,
            "captured_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "exit_code": proc.returncode,
            "transcript": f"screenshots/transcripts/{stem}.txt",
            "source_artifact": args.source,
            "blog_section": args.section,
            "caption": args.caption,
            "secret_check": "passed",
        }
    )
    log.write_text(json.dumps(entries, indent=1) + "\n")
    print(f"wrote {args.out} (exit={proc.returncode}, lines={len(output.splitlines())})")


if __name__ == "__main__":
    main()
