"""Deterministic comparison baselines. Weights were fixed a priori and were
not fitted to the reference rubric or to any Jev output.

B0  severity_only  : scanner/CVSS severity mapped straight to a disposition.
B1  context_points : a transparent additive points model over a small set of
                     contextual signals (the kind of spreadsheet formula many
                     teams use). It never outputs REVIEW.

Both baselines output (disposition, exposure 0-4, urgent bool).
"""

from __future__ import annotations

from .schemas import Conflict, cvss_severity, is_unknownish

SEVERITY_TO_DISPOSITION = {
    "CRITICAL": "EMERGENCY",
    "HIGH": "ACCELERATED",
    "MEDIUM": "STANDARD",
    "LOW": "DEFER",
}
SEVERITY_TO_EXPOSURE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

SEV_POINTS = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
ASSET_POINTS = {"critical": 2, "high": 1, "medium": 0, "low": 0}
CONTROL_PENALTY = {"effective": 2, "partial": 1, "none": 0}

# Shared thresholds for B1 (both domains).
B1_DISPOSITION_THRESHOLDS = [(10, "EMERGENCY"), (7, "ACCELERATED"), (4, "STANDARD"), (-99, "DEFER")]
B1_EXPOSURE_THRESHOLDS = [(11, 4), (8, 3), (5, 2), (3, 1), (-99, 0)]
B1_URGENT_THRESHOLD = 7


def _known(v):
    """Return value, or None when unknown / omitted / conflicting."""
    return None if is_unknownish(v) or isinstance(v, Conflict) else v


def _severity(domain: str, f: dict) -> str:
    return cvss_severity(f["cvss"]) if domain == "sca" else f["severity"]


def severity_only(domain: str, f: dict) -> dict:
    sev = _severity(domain, f)
    return {
        "disposition": SEVERITY_TO_DISPOSITION[sev],
        "exposure": SEVERITY_TO_EXPOSURE[sev],
        "urgent": sev in ("CRITICAL", "HIGH"),
    }


def context_points_score(domain: str, f: dict) -> int:
    pts = SEV_POINTS[_severity(domain, f)]
    if domain == "sca":
        pts += 3 if _known(f["kev"]) else 0
        epss = _known(f["epss"])
        pts += 0 if epss is None else 2 if epss >= 0.5 else 1 if epss >= 0.1 else 0
        pts += 1 if _known(f["internet"]) else 0
        reach = _known(f["reachable"])
        pts += 1 if reach is None else 2 if reach else 0
    else:
        ac = _known(f["attacker_controlled"])
        pts += 1 if ac is None else 3 if ac else 0
        reach = _known(f["reachable"])
        pts += 1 if reach is None else 2 if reach else 0
        pts += 1 if _known(f["internet"]) else 0
        san = _known(f["sanitization"])
        pts += 1 if san is None else {"none": 2, "partial": 1, "effective": 0}[san]
        pts += 1 if _known(f["auth"]) == "none" else 0
    pts += ASSET_POINTS.get(_known(f["asset"]), 0)
    pts -= CONTROL_PENALTY.get(_known(f["control"]), 0)
    return pts


def context_points(domain: str, f: dict) -> dict:
    pts = context_points_score(domain, f)
    disp = next(d for t, d in B1_DISPOSITION_THRESHOLDS if pts >= t)
    exp = next(e for t, e in B1_EXPOSURE_THRESHOLDS if pts >= t)
    return {"disposition": disp, "exposure": exp, "urgent": pts >= B1_URGENT_THRESHOLD, "points": pts}


BASELINES = {"severity_only": severity_only, "context_points": context_points}
