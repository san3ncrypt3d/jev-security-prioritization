"""Attribute domains, derived (mechanical) fields, and state rendering.

Facts are stored internally as a flat ``facts`` dict. Mechanical values
(CVSS severity band, EPSS band) are derived here in code and are never
asked of Jev. Rendering turns facts into the ``state`` object sent to Jev.

Special values for evidence fields:
    UNKNOWN            -> rendered as the string "unknown"
    OMIT               -> key removed from the state
    Conflict(a, b, ..) -> rendered as a dict of per-source claims
"""

from __future__ import annotations

from dataclasses import dataclass

UNKNOWN = "__unknown__"
OMIT = "__omit__"


@dataclass(frozen=True)
class Conflict:
    """Two evidence sources disagree about a field.

    ``values`` are the internal values each source asserts, ``sources`` the
    source names shown to Jev (same order).
    """

    field: str
    values: tuple
    sources: tuple


def is_unknownish(v) -> bool:
    return v == UNKNOWN or v == OMIT or isinstance(v, Conflict)


# ---------------------------------------------------------------------------
# Shared ordinal scales
# ---------------------------------------------------------------------------

CRITICALITY = ["low", "medium", "high", "critical"]
CONTROL = ["none", "partial", "effective"]

DISPOSITIONS = ["DEFER", "STANDARD", "ACCELERATED", "EMERGENCY", "REVIEW"]
# Priority rank for ordinal comparisons (REVIEW has no rank).
PRIORITY_RANK = {"DEFER": 0, "STANDARD": 1, "ACCELERATED": 2, "EMERGENCY": 3}
EXPOSURE_LEVELS = ["Minimal", "Low", "Moderate", "High", "Critical"]

# ---------------------------------------------------------------------------
# SCA
# ---------------------------------------------------------------------------

SCA_DOMAINS = {
    "cvss": [3.7, 5.3, 6.5, 7.5, 8.1, 9.8],
    "epss": [0.004, 0.03, 0.18, 0.72],
    "kev": [False, True],
    "exploit": ["none", "poc", "weaponized"],
    "internet": [False, True],
    "reachable": [False, True],
    "asset": CRITICALITY,
    "sensitive": [False, True],
    "privileges": ["none", "low", "high"],
    "complexity": ["low", "high"],
    "fix": [False, True],
    "control": CONTROL,
    "dependency": ["direct", "transitive"],
    "environment": ["production", "staging", "development"],
}

SCA_VULN_CLASSES = [
    ("deserialization of untrusted data", "decodeObject"),
    ("prototype pollution", "mergeDeep"),
    ("SQL injection in the query builder", "whereRaw"),
    ("XML external entity (XXE) processing", "parseDocument"),
    ("path traversal during archive extraction", "extractAll"),
    ("server-side request forgery (SSRF)", "fetchRemote"),
    ("authentication bypass in token validation", "verifyToken"),
    ("template injection leading to code execution", "renderTemplate"),
    ("HTTP request smuggling", "parseHeaders"),
    ("heap buffer overflow in image decoding", "decodeFrame"),
]

SCA_PACKAGES = [
    "libquartzite",
    "fernparse",
    "marrowdb-client",
    "opaline-xml",
    "tarrow",
    "wicketfetch",
    "sableauth",
    "glyphcraft",
    "hollowhttp",
    "prismimg",
    "cobaltcache",
    "junoqueue",
]

SERVICES = [
    "svc-orion",
    "svc-lyra",
    "svc-vega",
    "svc-altair",
    "svc-deneb",
    "svc-rigel",
    "svc-mira",
    "svc-castor",
    "svc-pollux",
    "svc-atlas",
]

EXPLOIT_TEXT = {
    "none": "none known",
    "poc": "public proof-of-concept exists",
    "weaponized": "weaponized exploit publicly available",
}

SCA_CONTROL_TEXT = {
    "none": "none",
    "partial": "partial: rate limiting only; no filtering of the vulnerable request pattern",
    "effective": "effective: verified virtual patch at the WAF blocks the vulnerable request pattern (enforcing mode)",
}

ENV_TEXT_SCA = {
    "production": "production",
    "staging": "staging",
    "development": "development only",
}


def cvss_severity(score: float) -> str:
    """CVSS v3 qualitative severity rating (FIRST specification)."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def epss_band(p: float) -> str:
    """Experiment-defined EPSS band (edges match the reference rubric)."""
    if p >= 0.5:
        return "high"
    if p >= 0.1:
        return "elevated"
    if p >= 0.01:
        return "low"
    return "very low"


# ---------------------------------------------------------------------------
# SAST
# ---------------------------------------------------------------------------

SAST_DOMAINS = {
    "severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    "attacker_controlled": [False, True],
    "reachable": [False, True],
    "sanitization": ["none", "partial", "effective"],
    "auth": ["none", "user", "admin"],
    "internet": [False, True],
    "privilege": ["restricted", "standard", "elevated"],
    "sensitive": [False, True],
    "preconditions": ["none", "moderate", "significant"],
    "asset": CRITICALITY,
    "control": CONTROL,
    "environment": ["production", "staging", "test_code"],
}

# (category, CWE, source template, sink, flow via, effective sanitizer text, partial text)
SAST_CATEGORIES = [
    (
        "SQL injection",
        "CWE-89",
        "`{p}` parameter of {c}.search()",
        "string-concatenated SQL passed to Statement.executeQuery()",
        "buildQuery()",
        "strict allow-list validation: value must match one of a fixed set of identifiers",
        "denylist filter strips single quotes only",
    ),
    (
        "OS command injection",
        "CWE-78",
        "`{p}` field of {c}.convert()",
        "value interpolated into a shell command run with shell=True",
        "buildCommand()",
        "strict allow-list validation: value must match a fixed set of format names",
        "denylist filter removes semicolons only",
    ),
    (
        "Path traversal",
        "CWE-22",
        "`{p}` parameter of {c}.download()",
        "value joined to a base directory and passed to open() for reading",
        "resolvePath()",
        "canonicalized path is verified to stay inside the base directory",
        "denylist filter removes the literal sequence '../' once",
    ),
    (
        "Server-side request forgery",
        "CWE-918",
        "`{p}` field of {c}.preview()",
        "value used as the URL for a server-side HTTP GET",
        "normalizeUrl()",
        "destination host must match a fixed allow-list of partner domains",
        "blocks the literal hostname 'localhost' only",
    ),
    (
        "Cross-site scripting (reflected)",
        "CWE-79",
        "`{p}` parameter of {c}.results()",
        "value written into an HTML response body",
        "formatBanner()",
        "contextual HTML output encoding applied by the template engine",
        "removes the literal string '<script' only",
    ),
    (
        "Insecure deserialization",
        "CWE-502",
        "`{p}` body of {c}.restore()",
        "bytes passed to a native object deserializer (pickle.loads)",
        "decodeSnapshot()",
        "payload is signature-verified with a server-held key before deserialization",
        "payload size is limited; content is not verified",
    ),
    (
        "Missing authorization (IDOR)",
        "CWE-639",
        "`{p}` path segment of {c}.getInvoice()",
        "record identifier used to load a record without an ownership check",
        "loadRecord()",
        "server-side ownership check verifies the record belongs to the caller",
        "check verifies the caller is logged in but not that they own the record",
    ),
    (
        "Unrestricted file upload",
        "CWE-434",
        "`{p}` multipart upload of {c}.attach()",
        "file saved under a web-served directory with a client-supplied extension",
        "storeFile()",
        "extension and content type restricted to an allow-list; files stored outside web root",
        "client-supplied MIME type is checked; extension is not",
    ),
    (
        "XML external entity processing",
        "CWE-611",
        "`{p}` XML body of {c}.importFeed()",
        "document parsed with external entity resolution enabled",
        "parseFeed()",
        "parser configured to disable DTDs and external entities before parsing",
        "entity expansion depth is limited; external entities remain enabled",
    ),
    (
        "Open redirect",
        "CWE-601",
        "`{p}` parameter of {c}.logout()",
        "value used as the Location header of an HTTP redirect",
        "buildRedirect()",
        "redirect target must be a relative path from a fixed allow-list",
        "checks that the value starts with 'http'",
    ),
]

PARAM_NAMES = ["q", "name", "target", "file", "url", "id", "doc", "ref", "token", "item"]
COMPONENT_NAMES = [
    "ReportController",
    "ExportHandler",
    "DocumentService",
    "LinkPreview",
    "SearchView",
    "SessionRestore",
    "InvoiceApi",
    "AttachmentService",
    "FeedImporter",
    "AuthRedirect",
]

SAST_AUTH_TEXT = {
    "none": "none (anonymous access)",
    "user": "any authenticated user",
    "admin": "administrator role only",
}

SAST_PRIVILEGE_TEXT = {
    "restricted": "sandboxed, least-privilege process",
    "standard": "standard service account",
    "elevated": "process runs with root/administrator privileges",
}

SAST_PRECONDITION_TEXT = {
    "none": "none",
    "moderate": "moderate: requires a specific non-default feature setting to be enabled",
    "significant": "significant: requires prior compromise of an internal system",
}

SAST_CONTROL_TEXT = {
    "none": "none",
    "partial": "partial: request logging and alerting only",
    "effective": "effective: verified WAF rule in enforcing mode blocks this input pattern on this route",
}

ENV_TEXT_SAST = {
    "production": "production",
    "staging": "staging",
    "test_code": "test code (not deployed)",
}


def sanitization_text(level: str, effective: str, partial: str) -> str:
    if level == "none":
        return "none: no validation or encoding on the path"
    if level == "partial":
        return f"partial: {partial}"
    return f"effective: {effective}"
