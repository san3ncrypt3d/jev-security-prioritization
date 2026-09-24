"""Experiment v1.1 addendum: 50,000-finding throughput and cost run.

Added after the v1.0 benchmark at the user's request, to measure throughput
and cost at scale. It reuses the frozen v1.0 sampler, renderer, rubric,
baselines and question definitions unchanged (imported, not modified), with a
new seed. Findings are drawn uniformly (NOT stratified), so agreement numbers
from this run describe a different case distribution than the v1.0 primary set.

Raw storage: append-only gzip JSONL shards, one per worker per session,
created in exclusive mode. Each record holds the full response body, HTTP
status, latency, attempt and the sha256 of the exact request payload (the
payload is reconstructible from data/scale_v1.1.jsonl.gz + question defs).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .baseline import BASELINES
from .client import DecisionsClient, build_payload, load_api_key, utcnow
from .datasets import _sast_random_facts, _sca_random_facts
from .provenance import ROOT
from .questions import QUESTIONS
from .reference import reference_label
from .render import render

SCALE_SEED = "20260923-scale-v1.1"
N_PER_DOMAIN = 25_000
WORKERS = 8
BUDGET_USD = 3.50
DATA = ROOT / "data/scale_v1.1.jsonl.gz"
RAW = ROOT / "results/raw/scale-v1.1"


def build() -> int:
    rng = {d: random.Random(f"{SCALE_SEED}-{d}") for d in ("sca", "sast")}
    n = 0
    with gzip.open(DATA, "xt") as fh:
        for i in range(N_PER_DOMAIN * 2):
            d = "sca" if i % 2 == 0 else "sast"
            r = rng[d]
            fid = f"{'OSV' if d == 'sca' else 'SAST'}-{r.randint(1000000, 9999999)}"
            f = (_sca_random_facts if d == "sca" else _sast_random_facts)(r, fid)
            ref = reference_label(d, f)
            fh.write(
                json.dumps(
                    {
                        "idx": i,
                        "domain": d,
                        "state": render(d, f),
                        "ref_disp": ref["disposition"],
                        "ref_exp": ref["exposure"],
                        "ref_urgent": ref["urgent"],
                        "b0": BASELINES["severity_only"](d, f),
                        "b1": BASELINES["context_points"](d, f),
                    }
                )
                + "\n"
            )
            n += 1
    return n


def load() -> list[dict]:
    with gzip.open(DATA, "rt") as fh:
        return [json.loads(line) for line in fh]


def done_indices() -> set[int]:
    done = set()
    for p in RAW.glob("*.jsonl.gz"):
        try:
            with gzip.open(p, "rt") as fh:
                for line in fh:
                    rec = json.loads(line)
                    if rec["error"] is None:
                        done.add(rec["idx"])
        except (EOFError, OSError):  # a shard cut off by an interrupted session: keep what was read
            pass
    return done


def run(limit: int | None = None, progress_every: int = 2500) -> dict:
    RAW.mkdir(parents=True, exist_ok=True)
    items = load()
    done = done_indices()
    todo = [x for x in items if x["idx"] not in done][:limit]
    session = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    key = load_api_key(ROOT / ".env")
    lock = threading.Lock()
    st = {"sent": 0, "ok": 0, "failed": 0, "cost": 0.0, "tokens": 0, "stopped_for_budget": False}
    t0 = time.time()
    local = threading.local()
    shards = []

    def worker_ctx():
        if not hasattr(local, "fh"):
            with lock:
                wid = len(shards)
                fh = gzip.open(RAW / f"{session}-w{wid:02d}.jsonl.gz", "xt")
                shards.append(fh)
            local.fh = fh
            local.client = DecisionsClient(key)
        return local

    def task(x):
        if st["stopped_for_budget"]:
            return
        ctx = worker_ctx()
        payload = build_payload(x["state"], QUESTIONS[x["domain"]])
        phash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        for attempt in (1, 2):
            rec = ctx.client._attempt(payload)
            rec.update(
                idx=x["idx"], domain=x["domain"], attempt=attempt, payload_sha256=phash, session=session
            )
            ctx.fh.write(json.dumps(rec) + "\n")
            if rec["error"] is None or rec["http_status"] not in (None, 429, 500, 502, 503, 504):
                break
            time.sleep(5)
        with lock:
            st["sent"] += 1
            if rec["error"] is None:
                st["ok"] += 1
                u = rec["response_body"].get("usage", {})
                st["cost"] += u.get("cost") or 0
                st["tokens"] += u.get("input_tokens") or 0
            else:
                st["failed"] += 1
            if st["cost"] >= BUDGET_USD:
                st["stopped_for_budget"] = True
            if st["sent"] % progress_every == 0 or st["sent"] == len(todo):
                el = time.time() - t0
                print(
                    f"[{utcnow()}] scale: {st['sent']:>6}/{len(todo)} ok={st['ok']} failed={st['failed']} "
                    f"tokens={st['tokens']:,} cost=${st['cost']:.4f} elapsed={el:.0f}s "
                    f"rate={st['sent'] / el:.1f} req/s",
                    flush=True,
                )

    print(
        f"[{utcnow()}] scale run: {len(todo)} findings to send ({len(done)} already done), "
        f"workers={WORKERS}, budget stop=${BUDGET_USD}",
        flush=True,
    )
    with ThreadPoolExecutor(WORKERS) as ex:
        list(ex.map(task, todo))
    for fh in shards:
        fh.close()
    st["wall_s"] = round(time.time() - t0, 1)
    st["req_per_s"] = round(st["sent"] / st["wall_s"], 2) if st["wall_s"] else None
    return st
