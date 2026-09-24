"""Record a REAL interactive terminal session (bash in a pseudo-terminal).

    python scripts/term_record.py NAME "cmd 1" "cmd 2" ... [--cols 100] [--rows 40]

A real `bash -i` runs in a PTY in the project directory with the project's
virtualenv activated (exactly as `source .venv/bin/activate` would). Commands
are typed into the PTY one at a time; the terminal's own echo, the prompt and
all program output are recorded byte-for-byte with timestamps to
screenshots/recordings/NAME.cast (asciinema-v2-style JSON lines). Nothing is
edited afterwards. The recording is refused if it contains a secret.

The prompt includes the standard OSC 133 "prompt start" shell-integration
mark (invisible in terminals) so the recorder knows when a command finished.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import re
import select
import struct
import sys
import tempfile
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARK = "\x1b]133;A\x07"
SECRET_PATTERNS = [re.compile(r"sk-or-[A-Za-z0-9_\-]{8,}"), re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{12,}")]


def secret_values() -> list[str]:
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
    return any(v in text for v in secret_values()) or any(p.search(text) for p in SECRET_PATTERNS)


def record(name: str, commands: list[str], cols: int, rows: int, timeout: float, typing_delay: float) -> Path:
    rc = tempfile.NamedTemporaryFile("w", suffix=".bashrc", delete=False)
    rc.write(
        "source .venv/bin/activate\n"
        f"PS1='\\[{MARK}\\](.venv) \\[\\e[01;34m\\]\\w\\[\\e[00m\\]\\$ '\n"
        "unset PROMPT_COMMAND; HISTFILE=/dev/null\n"
    )
    rc.close()
    env = {
        "HOME": os.environ["HOME"],
        "USER": os.environ.get("USER", ""),
        "LANG": "C.UTF-8",
        "TERM": "xterm-256color",
        "COLORTERM": "truecolor",
        "PATH": os.environ["PATH"],
        "PYTHONPATH": str(ROOT / "src"),
        "PYTHONUNBUFFERED": "1",
    }
    pid, fd = pty.fork()
    if pid == 0:  # child: a real interactive bash (window size set before bash starts)
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        os.chdir(ROOT)
        os.execvpe("bash", ["bash", "--noprofile", "--rcfile", rc.name, "-i"], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    events: list[tuple[float, str]] = []
    t0 = time.time()
    buf = ""

    def pump(until_prompts: int, limit: float) -> None:
        nonlocal buf
        deadline = time.time() + limit
        while buf.count(MARK) < until_prompts:
            if time.time() > deadline:
                raise TimeoutError("command did not finish in time")
            r, _, _ = select.select([fd], [], [], 0.2)
            if fd in r:
                try:
                    data = os.read(fd, 65536).decode("utf-8", "replace")
                except OSError:
                    return
                buf += data
                events.append((round(time.time() - t0, 3), data))

    pump(1, 30)  # initial prompt
    events.clear()  # drop shell start-up noise; the recording begins at the first clean prompt
    events.append((0.0, MARK + buf.split(MARK)[-1]))
    t0 = time.time()
    for i, cmd in enumerate(commands, start=2):
        for ch in cmd:  # typed into the PTY; bash/tty echo it back
            os.write(fd, ch.encode())
            time.sleep(typing_delay)
        os.write(fd, b"\r")
        pump(i, timeout)
    os.kill(pid, 9)
    os.unlink(rc.name)

    text = "".join(d for _, d in events)
    if contains_secret(text) or any(contains_secret(c) for c in commands):
        sys.exit("SECRET DETECTED: recording discarded")
    out = ROOT / "screenshots/recordings" / f"{name}.cast"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as fh:
        fh.write(
            json.dumps(
                {
                    "version": 2,
                    "width": cols,
                    "height": rows,
                    "timestamp": int(time.time()),
                    "env": {"TERM": "xterm-256color", "SHELL": "bash"},
                    "commands": commands,
                }
            )
            + "\n"
        )
        for t, d in events:
            fh.write(json.dumps([t, "o", d]) + "\n")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("commands", nargs="+")
    ap.add_argument("--cols", type=int, default=100)
    ap.add_argument("--rows", type=int, default=40)
    ap.add_argument("--timeout", type=float, default=3600)
    ap.add_argument("--typing-delay", type=float, default=0.004)
    a = ap.parse_args()
    print(record(a.name, a.commands, a.cols, a.rows, a.timeout, a.typing_delay))
