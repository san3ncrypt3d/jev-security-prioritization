"""Minimal, auditable client for the OpenRouter Decisions API.

* The API key is read from the environment (or a local .env file) and is
  only ever placed in the Authorization header. It is never logged, printed,
  or written to any record.
* Every attempt (success or failure) is written once to disk; files are opened
  in exclusive-create mode so raw results can never be overwritten.
* Retries are bounded: at most MAX_ATTEMPTS per request, only for transient
  statuses (429/5xx) or network timeouts, each attempt recorded separately.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import time
from pathlib import Path

import requests

ENDPOINT = "https://openrouter.ai/api/alpha/decisions"
MODEL = "typesafe/jev-1.13"
ENV_VAR = "OPENROUTER_API_KEY"
TIMEOUT_S = 60
MAX_ATTEMPTS = 2
RETRY_STATUSES = {429, 500, 502, 503, 504}
BACKOFF_S = 5.0

# Response headers that are safe and useful to keep.
KEEP_HEADERS = {
    "date",
    "content-type",
    "x-request-id",
    "x-generation-id",
    "cf-ray",
    "server",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
}


def load_api_key(env_file: str | Path = ".env") -> str:
    key = os.environ.get(ENV_VAR)
    if not key and Path(env_file).exists():
        for line in Path(env_file).read_text().splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[len("export ") :]
            if line.startswith(f"{ENV_VAR}="):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not key:
        raise RuntimeError(f"{ENV_VAR} is not set (environment or .env)")
    return key


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def build_payload(state, questions: dict, model: str = MODEL) -> dict:
    return {"model": model, "state": state, "questions": questions}


class DecisionsClient:
    def __init__(self, api_key: str, endpoint: str = ENDPOINT, timeout: float = TIMEOUT_S):
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "X-Title": "jev-security-prioritization-research",
            }
        )
        self.endpoint = endpoint
        self.timeout = timeout

    def __repr__(self) -> str:  # never expose the session headers
        return f"DecisionsClient(endpoint={self.endpoint!r})"

    def _attempt(self, payload: dict) -> dict:
        rec = {"utc_start": utcnow()}
        t0 = time.perf_counter()
        try:
            r = self._session.post(self.endpoint, json=payload, timeout=self.timeout)
            rec["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            rec["http_status"] = r.status_code
            rec["response_headers"] = {
                k.lower(): v for k, v in r.headers.items() if k.lower() in KEEP_HEADERS
            }
            try:
                rec["response_body"] = r.json()
            except ValueError:
                rec["response_body"] = None
                rec["response_text"] = r.text[:4000]
            rec["error"] = None if r.ok else f"HTTP {r.status_code}"
        except requests.RequestException as e:
            rec["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            rec["http_status"] = None
            rec["response_body"] = None
            rec["error"] = f"{type(e).__name__}: {str(e)[:500]}"
        rec["utc_end"] = utcnow()
        return rec

    def decide(self, payload: dict, raw_dir: Path, request_key: str, meta: dict | None = None) -> dict:
        """Send one request (bounded retries); persist every attempt. Returns final attempt record."""
        raw_dir.mkdir(parents=True, exist_ok=True)
        rec = {}
        for attempt in range(1, MAX_ATTEMPTS + 1):
            rec = self._attempt(payload)
            rec.update(
                request_key=request_key,
                attempt=attempt,
                endpoint=self.endpoint,
                request_payload=payload,
                meta=meta or {},
            )
            path = raw_dir / f"{request_key}__a{attempt}.json"
            with open(path, "x") as fh:  # exclusive create: never overwrite raw data
                json.dump(rec, fh, indent=1, ensure_ascii=False)
            transient = rec["http_status"] in RETRY_STATUSES or rec["http_status"] is None
            if rec["error"] is None or not transient or attempt == MAX_ATTEMPTS:
                break
            time.sleep(BACKOFF_S * attempt)
        return rec
