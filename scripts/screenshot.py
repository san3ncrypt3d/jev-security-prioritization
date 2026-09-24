"""Take a screenshot of a REAL terminal session.

    python scripts/screenshot.py OUT.png "cmd 1" ["cmd 2" ...] [--cols 100] [--rows 40]
        [--until TEXT --nth N] [--section S] [--caption C] [--source ARTIFACT]

1. scripts/term_record.py runs the commands in a real interactive bash inside
   a pseudo-terminal and records every byte (refused if a secret appears).
2. tools/screenshot/render.mjs replays that byte stream in xterm.js (a real
   terminal emulator) in headless Chrome and captures the window.
3. The entry is logged to screenshots/screenshots.json (-> screenshots/README.md).

Use --render-only to re-render a frame (e.g. a mid-run progress moment,
selected with --until/--nth) from an existing recording without re-running.
"""

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from term_record import record  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("out")
ap.add_argument("commands", nargs="*")
ap.add_argument("--cols", type=int, default=100)
ap.add_argument("--rows", type=int, default=40)
ap.add_argument("--timeout", type=float, default=7200)
ap.add_argument("--until")
ap.add_argument("--nth", default="1")
ap.add_argument("--recording", help="recording name (default: derived from OUT)")
ap.add_argument("--render-only", action="store_true")
ap.add_argument("--title", default="~/openrouter")
ap.add_argument("--section", default="")
ap.add_argument("--caption", default="")
ap.add_argument("--source", default="")
a = ap.parse_args()

name = a.recording or Path(a.out).relative_to("screenshots").with_suffix("").as_posix().replace("/", "__")
cast = ROOT / "screenshots/recordings" / f"{name}.cast"
if not a.render_only:
    if cast.exists():
        sys.exit(f"recording {cast.name} exists; recordings are never overwritten (use --render-only)")
    record(name, a.commands, a.cols, a.rows, a.timeout, 0.004)
cmd = ["node", str(ROOT / "tools/screenshot/render.mjs"), str(cast), str(ROOT / a.out), "--title", a.title]
if a.until:
    cmd += ["--until", a.until, "--nth", a.nth]
subprocess.run(cmd, check=True, capture_output=True)

header = json.loads(cast.read_text().splitlines()[0])
log = ROOT / "screenshots/screenshots.json"
entries = [e for e in (json.loads(log.read_text()) if log.exists() else []) if e["filename"] != a.out]
entries.append(
    {
        "filename": a.out,
        "commands": header["commands"],
        "recording": f"screenshots/recordings/{cast.name}",
        "frame": f"until '{a.until}' (occurrence {a.nth})" if a.until else "end of session",
        "recorded_utc": dt.datetime.fromtimestamp(header["timestamp"], dt.timezone.utc).isoformat(),
        "rendered_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "source_artifact": a.source,
        "blog_section": a.section,
        "caption": a.caption,
        "secret_check": "passed (recording refused otherwise)",
    }
)
log.write_text(json.dumps(entries, indent=1) + "\n")
print(f"wrote {a.out}")
