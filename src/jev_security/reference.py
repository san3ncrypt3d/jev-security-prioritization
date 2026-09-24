"""Reference rubric: an explicit, deterministic *experimental* policy.

This is NOT ground truth. It is one transparent security-prioritization
policy, written before any Jev output was observed, against which Jev and
the baselines are compared. See ``docs``/manifest for the full rationale.

Structure (both domains):

    THREAT  (0-3): how realistic an exploitation path is in this deployment
    IMPACT  (0-3): how much harm a successful exploit would do
    EXPOSURE(0-4): combination of THREAT and IMPACT
                   THREAT == 0  -> 1 if IMPACT == 3 else 0
                   otherwise    -> clamp(THREAT + IMPACT - 2, 1, 4)
                   plus a domain-specific floor rule (see below)
    DISPOSITION  : 0 -> DEFER, 1-2 -> STANDARD, 3 -> ACCELERATED, 4 -> EMERGENCY
    URGENT       : EXPOSURE >= 3  (i.e. ACCELERATED or EMERGENCY)

Unknown, omitted, or conflicting evidence: the rubric is evaluated for every
possible value of each uncertain field (conflicts: only the asserted values).
If all completions give the same disposition, that disposition is the
reference; otherwise the reference is REVIEW. The same agreement rule is
applied independently to EXPOSURE and URGENT (disagreement -> None, i.e. the
case has no determinate reference for that question).
"""

from __future__ import annotations

import itertools

from .schemas import (
    CONTROL,
    CRITICALITY,
    SAST_DOMAINS,
    SCA_DOMAINS,
    Conflict,
    is_unknownish,
)

DISPOSITION_BY_EXPOSURE = {0: "DEFER", 1: "STANDARD", 2: "STANDARD", 3: "ACCELERATED", 4: "EMERGENCY"}

# Fields whose uncertainty the rubric reasons about (others are always known).
SCA_UNCERTAIN_FIELDS = ["reachable", "internet", "epss", "asset", "exploit", "control"]
SAST_UNCERTAIN_FIELDS = ["attacker_controlled", "reachable", "sanitization", "internet", "asset", "auth"]


def _clamp(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, x))


def _combine(threat: int, impact: int) -> int:
    if threat == 0:
        return 1 if impact == 3 else 0
    return _clamp(threat + impact - 2, 1, 4)


def _cvss_level(score: float) -> int:
    return 3 if score >= 9.0 else 2 if score >= 7.0 else 1 if score >= 4.0 else 0


# ---------------------------------------------------------------------------
# SCA
# ---------------------------------------------------------------------------


def sca_core(f: dict) -> dict:
    """Rubric for a fully-known SCA fact set."""
    if not f["reachable"]:
        threat = 0
    else:
        if f["kev"]:
            x = 3
        elif f["epss"] >= 0.5 or f["exploit"] == "weaponized":
            x = 2
        elif f["epss"] >= 0.1 or f["exploit"] == "poc":
            x = 1
        else:
            x = 0
        x += 1 if f["internet"] else 0
        x -= 1 if f["privileges"] == "high" else 0
        x -= CONTROL.index(f["control"])  # none 0, partial 1, effective 2
        threat = _clamp(x, 0, 3)

    a = CRITICALITY.index(f["asset"])
    i = (_cvss_level(f["cvss"]) + a + 1) // 2
    i += 1 if f["sensitive"] else 0
    i -= {"production": 0, "staging": 1, "development": 2}[f["environment"]]
    impact = _clamp(i, 0, 3)

    exposure = _combine(threat, impact)
    # Floor: known exploitation of a reachable, internet-facing production
    # component without an effective control is always at least High.
    if (
        f["kev"]
        and f["reachable"]
        and f["internet"]
        and f["control"] != "effective"
        and f["environment"] == "production"
    ):
        exposure = max(exposure, 3)
    return {"threat": threat, "impact": impact, "exposure": exposure}


# ---------------------------------------------------------------------------
# SAST
# ---------------------------------------------------------------------------


def sast_core(f: dict) -> dict:
    """Rubric for a fully-known SAST fact set."""
    if (
        not f["attacker_controlled"]
        or not f["reachable"]
        or f["sanitization"] == "effective"
        or f["environment"] == "test_code"
    ):
        threat = 0
    else:
        x = 2 + (1 if f["sanitization"] == "none" else 0)
        x += 1 if f["internet"] else 0
        x -= {"none": 0, "user": 1, "admin": 2}[f["auth"]]
        x -= 1 if f["preconditions"] == "significant" else 0
        x -= CONTROL.index(f["control"])
        threat = _clamp(x, 0, 3)

    a = CRITICALITY.index(f["asset"])
    sev = SAST_DOMAINS["severity"].index(f["severity"])  # LOW 0 .. CRITICAL 3
    i = (sev + a + 1) // 2
    i += 1 if f["sensitive"] else 0
    i += 1 if f["privilege"] == "elevated" else 0
    i -= 1 if f["environment"] == "staging" else 0
    if f["environment"] == "test_code":
        i = 0  # code that is not deployed has no deployment impact
    impact = _clamp(i, 0, 3)

    exposure = _combine(threat, impact)
    # Floor: an unauthenticated, internet-facing, attacker-controlled,
    # reachable, unsanitized flow into a high/critical production component
    # without an effective control is always at least High.
    if (
        f["attacker_controlled"]
        and f["reachable"]
        and f["sanitization"] == "none"
        and f["internet"]
        and f["auth"] == "none"
        and f["control"] != "effective"
        and f["environment"] == "production"
        and a >= 2
    ):
        exposure = max(exposure, 3)
    return {"threat": threat, "impact": impact, "exposure": exposure}


# ---------------------------------------------------------------------------
# Uncertainty handling
# ---------------------------------------------------------------------------


def _completions(facts: dict, domains: dict, fields: list[str]):
    uncertain = [k for k in fields if is_unknownish(facts.get(k))]
    options = []
    for k in uncertain:
        v = facts[k]
        options.append(list(v.values) if isinstance(v, Conflict) else list(domains[k]))
    for combo in itertools.product(*options):
        g = dict(facts)
        g.update(dict(zip(uncertain, combo)))
        yield g
    # itertools.product of zero iterables yields one empty tuple, so a fully
    # known fact set yields exactly itself.


def reference_label(domain: str, facts: dict) -> dict:
    core, domains, fields = (
        (sca_core, SCA_DOMAINS, SCA_UNCERTAIN_FIELDS)
        if domain == "sca"
        else (sast_core, SAST_DOMAINS, SAST_UNCERTAIN_FIELDS)
    )
    results = [core(g) for g in _completions(facts, domains, fields)]
    exposures = sorted({r["exposure"] for r in results})
    dispositions = {DISPOSITION_BY_EXPOSURE[e] for e in exposures}
    urgents = {e >= 3 for e in exposures}
    determinate = len(results) == 1
    return {
        "disposition": dispositions.pop() if len(dispositions) == 1 else "REVIEW",
        "exposure": exposures[0] if len(exposures) == 1 else None,
        "exposure_range": [exposures[0], exposures[-1]],
        "urgent": urgents.pop() if len(urgents) == 1 else None,
        "fully_known": determinate,
        "threat": results[0]["threat"] if determinate else None,
        "impact": results[0]["impact"] if determinate else None,
        "n_completions": len(results),
    }
