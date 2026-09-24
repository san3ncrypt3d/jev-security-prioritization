"""Experiment planning and execution.

Phases (execution gates):
    sca_main    : SCA main + contradiction + inconsistent cases
    sast_main   : SAST main + contradiction + inconsistent cases
    secondary   : counterfactual, missing, adversarial, paraphrase, repeat (both domains)

Identical (domain, state) pairs share one request (``request_key``); the
repeat experiment deliberately re-sends identical payloads under distinct keys.
Within each phase the request order is shuffled with a fixed seed so request
time is not confounded with case type. A run can be resumed: keys that
already have a successful raw record in the run directory are never re-sent.
"""

from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

from .client import DecisionsClient, build_payload, load_api_key, utcnow
from .provenance import ROOT, git_commit, load_hashes, software_versions, verify_frozen
from .questions import QUESTIONS

PHASES = {
    "sca_main": ("sca", {"main", "contradiction", "inconsistent"}),
    "sast_main": ("sast", {"main", "contradiction", "inconsistent"}),
    "secondary": (None, {"counterfactual", "missing", "adversarial", "paraphrase", "repeat"}),
}
PHASE_ORDER = ["sca_main", "sast_main", "secondary"]
INTER_REQUEST_DELAY_S = 0.35
ORDER_SEED = 20260923


def load_cases(domain: str | None = None) -> list[dict]:
    out = []
    for d in ("sca", "sast"):
        if domain in (None, d):
            out += json.loads((ROOT / f"data/{d}_cases.json").read_text())["cases"]
    return out


def plan_requests(phase: str | None = None) -> list[dict]:
    """Unique requests for a phase (or all phases), in execution order."""
    seen: set[str] = set()
    plan = []
    for ph in PHASE_ORDER if phase is None else [phase]:
        domain, exps = PHASES[ph]
        items = []
        for c in load_cases(domain):
            if c["experiment"] not in exps or c["request_key"] in seen:
                continue
            seen.add(c["request_key"])
            items.append(
                {
                    "phase": ph,
                    "request_key": c["request_key"],
                    "domain": c["domain"],
                    "first_case_id": c["case_id"],
                    "state": c["state"],
                }
            )
        random.Random(f"{ORDER_SEED}-{ph}").shuffle(items)
        plan += items
    if phase is not None:  # drop keys already covered by earlier phases
        earlier = set()
        for ph in PHASE_ORDER[: PHASE_ORDER.index(phase)]:
            earlier |= {p["request_key"] for p in plan_requests(ph)}
        plan = [p for p in plan if p["request_key"] not in earlier]
    return plan


def successful_keys(raw_dir: Path) -> set[str]:
    keys = set()
    if raw_dir.exists():
        for p in raw_dir.glob("*.json"):
            rec = json.loads(p.read_text())
            if rec.get("error") is None:
                keys.add(rec["request_key"])
    return keys


def write_run_provenance(run_dir: Path, run_id: str) -> None:
    path = run_dir / "run_provenance.json"
    if path.exists():
        return
    hashes = load_hashes()
    prov = {
        "run_id": run_id,
        "created_utc": utcnow(),
        "requested_model": hashes["model_requested"],
        "endpoint": hashes["endpoint"],
        "experiment_version": hashes["experiment_version"],
        "git_commit": git_commit(),
        "software": software_versions(),
        "frozen_artifact_sha256": hashes["sha256"],
        "random_seed": hashes["random_seed"],
    }
    run_dir.mkdir(parents=True, exist_ok=True)
    with open(path, "x") as fh:
        json.dump(prov, fh, indent=2)


def run_phase(phase: str, run_id: str, limit: int | None = None, progress_every: int = 25) -> dict:
    changed = verify_frozen()
    if changed:
        raise SystemExit(
            f"Frozen artifacts changed since freeze: {changed}. Create a new experiment version."
        )
    run_dir = ROOT / "results/raw" / run_id
    write_run_provenance(run_dir, run_id)
    raw_dir = run_dir / "responses"
    done = successful_keys(raw_dir)
    plan = [p for p in plan_requests(phase) if p["request_key"] not in done]
    if limit is not None:
        plan = plan[:limit]
    client = DecisionsClient(load_api_key(ROOT / ".env"))
    stats = {"sent": 0, "ok": 0, "failed": 0, "cost": 0.0, "input_tokens": 0}
    t0 = time.time()
    print(f"[{utcnow()}] phase={phase} run={run_id} to_send={len(plan)} already_done={len(done)}", flush=True)
    for i, p in enumerate(plan, 1):
        payload = build_payload(p["state"], QUESTIONS[p["domain"]])
        rec = client.decide(
            payload,
            raw_dir,
            p["request_key"],
            meta={"phase": phase, "run_id": run_id, "first_case_id": p["first_case_id"]},
        )
        stats["sent"] += 1
        if rec["error"] is None:
            stats["ok"] += 1
            u = (rec["response_body"] or {}).get("usage", {})
            stats["cost"] += u.get("cost") or 0.0
            stats["input_tokens"] += u.get("input_tokens") or 0
        else:
            stats["failed"] += 1
            print(f"  ! {p['request_key']} failed: {rec['error']}", flush=True)
        if i % progress_every == 0 or i == len(plan):
            print(
                f"[{utcnow()}] {phase}: {i}/{len(plan)} ok={stats['ok']} failed={stats['failed']} "
                f"input_tokens={stats['input_tokens']} cost=${stats['cost']:.6f} "
                f"elapsed={time.time() - t0:.0f}s",
                flush=True,
            )
        time.sleep(INTER_REQUEST_DELAY_S)
    return stats


if __name__ == "__main__":  # pragma: no cover
    print("use scripts/run_experiment.py", file=sys.stderr)
