"""Experiment v2: extracting fields from raw evidence (Jev vs regex vs Claude Sonnet 5).

python scripts/v2.py freeze     # write data/v2_findings.json + experiments/v2_manifest.json (hashes)
python scripts/v2.py estimate   # request count and cost estimate
python scripts/v2.py run        # Jev on all 450, Sonnet 5 on the stratified 150 (resumable, write-once)
"""

import argparse
import json
import random
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jev_security import v2_evidence as V  # noqa: E402
from jev_security import v2_shift as VB  # noqa: E402
from jev_security.client import DecisionsClient, build_payload, load_api_key, utcnow  # noqa: E402
from jev_security.provenance import sha256_file, software_versions, verify_frozen  # noqa: E402

DATA = ROOT / "data/v2_findings.json"
MAN = ROOT / "experiments/v2_manifest.json"
RAW = ROOT / "results/raw/v2"
SONNET = "anthropic/claude-sonnet-5"
CHAT = "https://openrouter.ai/api/v1/chat/completions"
SONNET_PER_SET = 75
BUDGET_USD = 1.20
FILES = [
    "src/jev_security/v2_evidence.py",
    "src/jev_security/v2_shift.py",
    "scripts/v2.py",
    "data/v2_findings.json",
]

SONNET_SYSTEM = (
    "You extract facts about a static-analysis finding from its raw evidence. Answer every question about the "
    "evidence you are given. Respond with ONLY a JSON object with exactly these keys: "
    '"attacker_controlled" (probability 0-1 that the answer is yes), "reachable" (probability 0-1), '
    '"sanitization" (one of none, partial, effective), "auth" (one of none, user, admin), '
    '"internet" (probability 0-1), "test_code" (probability 0-1), "sensitive" (probability 0-1).'
)


def load():
    return json.loads(DATA.read_text())["findings"]


def sonnet_subset(findings):
    rng = random.Random("20260924-v2-sonnet-subset")
    out = []
    for s in ("A", "B"):
        pool = [f for f in findings if f["set"] == s]
        urg = [f for f in pool if f["reference"]["urgent"]]
        rest = [f for f in pool if not f["reference"]["urgent"]]
        k = round(SONNET_PER_SET * len(urg) / len(pool))
        out += rng.sample(urg, k) + rng.sample(rest, SONNET_PER_SET - k)
    return {f["finding_id"] for f in out}


def sonnet_payload(state):
    qs = {
        k: {"question": q["instructions"], "answer_options": q["criteria"]} for k, q in V.V2_QUESTIONS.items()
    }
    return {
        "model": SONNET,
        "temperature": 0,
        "max_tokens": 600,
        "response_format": {"type": "json_object"},
        "reasoning": {"effort": "minimal"},
        "usage": {"include": True},
        "messages": [
            {"role": "system", "content": SONNET_SYSTEM},
            {"role": "user", "content": json.dumps({"evidence": state, "questions": qs})},
        ],
    }


def write_once(path: Path, rec: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "x") as fh:
        json.dump(rec, fh, indent=1)


ap = argparse.ArgumentParser()
ap.add_argument("cmd", choices=["freeze", "estimate", "run"])
a = ap.parse_args()

if a.cmd == "freeze":
    if MAN.exists():
        sys.exit("v2 already frozen")
    A = V.build()
    for f in A:
        f["set"] = "A"
    B = VB.build()
    findings = A + B
    DATA.write_text(
        json.dumps(
            {
                "note": "Synthetic SAST findings with raw evidence; truth known by construction.",
                "findings": findings,
            },
            indent=1,
        )
        + "\n"
    )
    MAN.write_text(
        json.dumps(
            {
                "experiment_version": "2.0.0",
                "question": "Given only RAW evidence, can Jev produce the fields a deterministic rule needs, and does that "
                "reduce human review while still catching urgent findings?",
                "why": "v1 gave Jev pre-verified fields, where a rule (or the human who verified them) needs no model.",
                "sets": {
                    "A": f"{len(A)} findings, Flask + Express idioms; the regex baseline was written with these templates "
                    "in mind (biased toward regex)",
                    "B": f"{len(B)} findings, FastAPI + NestJS + Terraform idioms written after the regex and Jev "
                    "questions were committed (git f309979); author knew the regex, so biased against it",
                },
                "fields_extracted": V.FIELDS,
                "given_as_facts": [
                    "scanner severity (by category)",
                    "asset criticality",
                    "process privilege",
                    "exploit preconditions",
                    "compensating control",
                ],
                "decision_rule": "frozen v1 rubric reference.sast_core, identical for every pipeline",
                "pipelines": {
                    "oracle": "true fields -> rule (ceiling; equals the reference by construction)",
                    "severity_only": "scanner severity HIGH/CRITICAL -> human",
                    "regex": "v2_evidence.regex_fields -> rule",
                    "jev": "one Decisions request per finding, 7 questions (5 Noul, 2 Choice), p>=0.5 / argmax -> rule",
                    "jev_routed": "jev, plus send to a human any finding with a Noul in [0.25, 0.75] or a Choice confidence < 0.40",
                    "sonnet": f"{SONNET}, same questions as a JSON prompt, reasoning minimal, on a stratified subset of "
                    f"{SONNET_PER_SET} per set",
                },
                "human_queue_policy": "findings predicted urgent (exposure >= 3) are verified by a human; jev_routed also "
                "sends uncertain findings",
                "metrics": [
                    "field accuracy per set",
                    "urgent recall and number of urgent findings missed",
                    "human queue size (share of all findings)",
                    "precision of the queue",
                    "Noul Brier score per field",
                    "latency, tokens, cost",
                ],
                "thresholds": {
                    "noul_yes": 0.5,
                    "noul_uncertain": list(V.NOUL_UNCERTAIN),
                    "choice_conf_min": V.CHOICE_CONF_MIN,
                },
                "sonnet_subset": sorted(sonnet_subset(findings)),
                "budget_stop_usd": BUDGET_USD,
                "exclusions": "failed or unparseable responses are reported, not re-run",
                "software": software_versions(),
                "sha256": {f: sha256_file(ROOT / f) for f in FILES},
            },
            indent=1,
        )
        + "\n"
    )
    print(
        f"frozen: {len(A)} + {len(B)} findings; urgent A={sum(f['reference']['urgent'] for f in A)} "
        f"B={sum(f['reference']['urgent'] for f in B)}"
    )
    sys.exit(0)

man = json.loads(MAN.read_text())
bad = [f for f, h in man["sha256"].items() if sha256_file(ROOT / f) != h]
if bad or verify_frozen():
    sys.exit(f"frozen artifacts changed: {bad}")
findings = load()
sub = set(man["sonnet_subset"])

if a.cmd == "estimate":
    jc = sum(len(json.dumps(build_payload(f["state"], V.V2_QUESTIONS))) for f in findings)
    sc = sum(len(json.dumps(sonnet_payload(f["state"]))) for f in findings if f["finding_id"] in sub)
    jev_tok = jc * 1215 / 5044  # chars->tokens ratio measured on the v1 smoke test
    son_tok = sc / 3.4
    jev_cost = jev_tok * 0.042e-6
    son_cost = son_tok * 2e-6 + len(sub) * 150 * 10e-6
    print(f"Jev: {len(findings)} requests, ~{jev_tok:,.0f} input tokens, ~${jev_cost:.3f}")
    print(
        f"Sonnet 5: {len(sub)} requests, ~{son_tok:,.0f} input tokens (+~150 output each), ~${son_cost:.3f}"
    )
    print(f"Total estimate ~${jev_cost + son_cost:.2f}; budget stop ${BUDGET_USD}")
    sys.exit(0)

key = load_api_key(ROOT / ".env")
jev = DecisionsClient(key)
sess = requests.Session()
sess.headers.update({"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
spent = 0.0
order = list(findings)
random.Random("20260924-v2-order").shuffle(order)
print(f"[{utcnow()}] v2 run: {len(order)} findings (Jev) + {len(sub)} (Sonnet 5), sequential", flush=True)
for n, f in enumerate(order, 1):
    fid = f["finding_id"]
    jobs = [("jev", RAW / "jev" / f"{fid}.json")]
    if fid in sub:
        jobs.append(("sonnet", RAW / "sonnet" / f"{fid}.json"))
    random.Random(fid).shuffle(jobs)
    for who, path in jobs:
        if path.exists():
            continue
        if spent >= BUDGET_USD:
            sys.exit(f"budget stop at ${spent:.4f}")
        if who == "jev":
            payload = build_payload(f["state"], V.V2_QUESTIONS)
            rec = jev._attempt(payload)
        else:
            payload = sonnet_payload(f["state"])
            rec = {"utc_start": utcnow()}
            t0 = time.perf_counter()
            try:
                r = sess.post(CHAT, json=payload, timeout=120)
                rec.update(
                    latency_ms=round((time.perf_counter() - t0) * 1000, 1),
                    http_status=r.status_code,
                    response_body=r.json()
                    if r.headers.get("content-type", "").startswith("application/json")
                    else None,
                    error=None if r.ok else f"HTTP {r.status_code}",
                )
            except requests.RequestException as e:
                rec.update(
                    latency_ms=round((time.perf_counter() - t0) * 1000, 1),
                    http_status=None,
                    response_body=None,
                    error=f"{type(e).__name__}: {str(e)[:300]}",
                )
            rec["utc_end"] = utcnow()
        rec.update(finding_id=fid, pipeline=who, request_payload=payload)
        write_once(path, rec)
        spent += ((rec.get("response_body") or {}).get("usage") or {}).get("cost") or 0.0
        time.sleep(0.3)
    if n % 50 == 0 or n == len(order):
        print(f"[{utcnow()}] v2: {n}/{len(order)} findings done, spent=${spent:.4f}", flush=True)
print(json.dumps({"spent_usd": round(spent, 6)}))
