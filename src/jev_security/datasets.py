"""Seeded, rule-based generation of all synthetic SCA and SAST cases.

Every case carries:
    facts      : serialized internal facts (unknown/omitted/conflict encoded)
    state      : the exact object/string sent to Jev
    reference  : reference-rubric labels (computed here, before any Jev call)
    baselines  : B0 / B1 outputs
    request_key: sha256 of (domain, state) [+ repeat index]; identical states
                 share one API request.

Experiments (the ``experiment`` field):
    main           stratified random sample, 20 cases per reference exposure level
    contradiction  severity vs. context disagree (rule-generated, 6 + 6)
    inconsistent   two evidence sources disagree on one decision-relevant field
    missing        one field set to "unknown" or omitted (anchor = main case)
    counterfactual one attribute toggled low->high on shared random contexts
                   (15 contexts, stratified 3 per reference exposure level)
    adversarial    untrusted text appended to the description (anchor = main case)
    paraphrase     reworded description / alternative keys / prose (anchor = main case)
    repeat         identical request re-sent 3 more times (anchor = main case)
"""

from __future__ import annotations

import hashlib
import json
import random

from .baseline import BASELINES
from .reference import reference_label
from .render import render
from .schemas import (
    COMPONENT_NAMES,
    OMIT,
    PARAM_NAMES,
    SAST_CATEGORIES,
    SAST_DOMAINS,
    SCA_DOMAINS,
    SCA_PACKAGES,
    SCA_VULN_CLASSES,
    SERVICES,
    UNKNOWN,
    Conflict,
)

SEED = 20260923
N_MAIN_PER_LEVEL = 20
N_CONTRADICTION_EACH = 6
N_INCONSISTENT = 10
N_MISSING_BASES = 10
N_CF_CONTEXTS = 15  # 3 contexts per reference exposure level 0-4
N_ADV_BASES = 10
N_PARA_BASES = 10
N_REPEAT_BASES = 10
N_REPEATS = 3

SCA_MISSING_FIELDS = ["reachable", "epss", "asset", "internet"]
SAST_MISSING_FIELDS = ["sanitization", "attacker_controlled", "reachable", "asset"]

# (attribute, low value, high value) — "high" is the riskier value.
SCA_TOGGLES = [
    ("kev", False, True),
    ("epss", 0.004, 0.72),
    ("internet", False, True),
    ("reachable", False, True),
    ("asset", "low", "critical"),
    ("control", "effective", "none"),
    ("cvss", 5.3, 9.8),
]
SAST_TOGGLES = [
    ("attacker_controlled", False, True),
    ("reachable", False, True),
    ("internet", False, True),
    ("sanitization", "effective", "none"),
    ("auth", "user", "none"),
    ("asset", "low", "critical"),
    ("severity", "MEDIUM", "CRITICAL"),
]

SCA_CONFLICTS = [
    ("reachable", (False, True), ("static_call_graph_analysis", "runtime_instrumentation")),
    ("internet", (False, True), ("asset_inventory", "external_attack_surface_scan")),
    ("exploit", ("none", "weaponized"), ("vulnerability_database", "threat_intel_feed")),
    ("asset", ("low", "critical"), ("cmdb_record", "service_owner_statement")),
    ("control", ("effective", "none"), ("security_team_record", "latest_config_audit")),
]
SAST_CONFLICTS = [
    ("attacker_controlled", (False, True), ("scanner_taint_model", "manual_code_review")),
    ("reachable", (False, True), ("scanner_call_graph", "runtime_trace")),
    ("sanitization", ("effective", "none"), ("developer_comment", "security_review")),
    ("internet", (False, True), ("asset_inventory", "external_attack_surface_scan")),
    ("auth", ("admin", "none"), ("route_configuration", "penetration_test_note")),
]


# ---------------------------------------------------------------------------
# Fact sampling
# ---------------------------------------------------------------------------


def _sca_random_facts(rng: random.Random, fid: str) -> dict:
    vc, fn = rng.choice(SCA_VULN_CLASSES)
    f = {k: rng.choice(v) for k, v in SCA_DOMAINS.items()}
    f.update(
        finding_id=fid,
        package=rng.choice(SCA_PACKAGES),
        version=f"{rng.randint(1, 6)}.{rng.randint(0, 19)}.{rng.randint(0, 9)}",
        vuln_class=vc,
        function=fn,
        service=rng.choice(SERVICES),
    )
    # KEV-listed vulnerabilities have known exploitation, so exploit "none" is inconsistent.
    if f["kev"] and f["exploit"] == "none":
        f["exploit"] = "weaponized"
    return f


def _sast_random_facts(rng: random.Random, fid: str) -> dict:
    cat, cwe, src, sink, via, eff, part = rng.choice(SAST_CATEGORIES)
    comp = rng.choice(COMPONENT_NAMES)
    p = rng.choice(PARAM_NAMES)
    f = {k: rng.choice(v) for k, v in SAST_DOMAINS.items()}
    f.update(
        finding_id=fid,
        category=cat,
        cwe=cwe,
        component=comp,
        rule_id=f"R{rng.randint(1000, 9999)}",
        source=src.format(p=p, c=comp),
        sink=sink,
        code_flow=f"`{p}` -> {via} -> sink",
        san_effective=eff,
        san_partial=part,
    )
    return f


def _sample(domain, rng, fid):
    return (_sca_random_facts if domain == "sca" else _sast_random_facts)(rng, fid)


def _fid(domain: str, rng: random.Random) -> str:
    return f"{'OSV' if domain == 'sca' else 'SAST'}-{rng.randint(100000, 999999)}"


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def serialize_facts(f: dict) -> dict:
    out = {}
    for k, v in f.items():
        if isinstance(v, Conflict):
            out[k] = {"__conflict__": {"values": list(v.values), "sources": list(v.sources)}}
        else:
            out[k] = v
    return out


def deserialize_facts(d: dict) -> dict:
    out = {}
    for k, v in d.items():
        if isinstance(v, dict) and "__conflict__" in v:
            c = v["__conflict__"]
            out[k] = Conflict(k, tuple(c["values"]), tuple(c["sources"]))
        else:
            out[k] = v
    return out


def state_key(domain: str, state, repeat: int = 0) -> str:
    blob = json.dumps({"domain": domain, "state": state}, sort_keys=True, ensure_ascii=False)
    h = hashlib.sha256(blob.encode()).hexdigest()[:24]
    return f"{domain}-{h}" + (f"-rep{repeat}" if repeat else "")


def make_case(
    domain,
    experiment,
    case_id,
    facts,
    *,
    group=None,
    variant=None,
    attribute=None,
    representation="canonical",
    description_variant="A",
    adversarial=None,
    repeat=0,
    anchor=None,
    tags=None,
):
    state = render(
        domain,
        facts,
        representation=representation,
        description_variant=description_variant,
        adversarial=adversarial,
    )
    # Baselines and rubric read structured facts only (free text is ignored by design).
    return {
        "case_id": case_id,
        "domain": domain,
        "experiment": experiment,
        "group": group,
        "variant": variant,
        "attribute": attribute,
        "anchor_case_id": anchor,
        "tags": tags or [],
        "render": {
            "representation": representation,
            "description_variant": description_variant,
            "adversarial": adversarial,
        },
        "facts": serialize_facts(facts),
        "state": state,
        "request_key": state_key(domain, state, repeat),
        "reference": reference_label(domain, facts),
        "baselines": {name: fn(domain, facts) for name, fn in BASELINES.items()},
    }


# ---------------------------------------------------------------------------
# Experiment builders
# ---------------------------------------------------------------------------


def build_main(domain, rng):
    buckets = {e: [] for e in range(5)}
    i = 0
    while any(len(b) < N_MAIN_PER_LEVEL for b in buckets.values()):
        i += 1
        if i > 200000:
            raise RuntimeError("could not fill strata")
        f = _sample(domain, rng, _fid(domain, rng))
        e = reference_label(domain, f)["exposure"]
        if len(buckets[e]) < N_MAIN_PER_LEVEL:
            buckets[e].append(f)
    facts = [f for e in range(5) for f in buckets[e]]
    rng.shuffle(facts)
    return [make_case(domain, "main", f"{domain}-main-{n:03d}", f) for n, f in enumerate(facts, 1)]


def _hs_lc_ok(domain, f):
    """High severity, low context."""
    if domain == "sca":
        mitig = [
            not f["internet"],
            not f["reachable"],
            f["control"] == "effective",
            f["asset"] == "low",
            f["environment"] == "development",
        ]
        return (
            f["cvss"] >= 8.1
            and f["epss"] < 0.1
            and not f["kev"]
            and f["exploit"] == "none"
            and sum(mitig) >= 2
        )
    mitig = [
        not f["attacker_controlled"],
        not f["reachable"],
        f["sanitization"] == "effective",
        f["environment"] == "test_code",
    ]
    return f["severity"] in ("CRITICAL", "HIGH") and sum(mitig) >= 1


def _ls_hc_ok(domain, f):
    """Lower severity, strong exploitation context."""
    if domain == "sca":
        return (
            f["cvss"] in (5.3, 6.5)
            and (f["kev"] or f["epss"] >= 0.5)
            and f["internet"]
            and f["reachable"]
            and f["asset"] in ("high", "critical")
            and f["control"] == "none"
            and f["environment"] == "production"
        )
    return (
        f["severity"] in ("MEDIUM", "LOW")
        and f["attacker_controlled"]
        and f["reachable"]
        and f["internet"]
        and f["auth"] == "none"
        and f["sanitization"] == "none"
        and f["asset"] in ("high", "critical")
        and f["sensitive"]
        and f["control"] == "none"
        and f["environment"] == "production"
    )


def build_contradiction(domain, rng):
    cases = []
    for kind, ok in (("high_severity_low_context", _hs_lc_ok), ("low_severity_high_context", _ls_hc_ok)):
        n = 0
        while n < N_CONTRADICTION_EACH:
            f = _sample(domain, rng, _fid(domain, rng))
            if ok(domain, f):
                n += 1
                cases.append(
                    make_case(
                        domain,
                        "contradiction",
                        f"{domain}-contra-{kind[:4]}-{n:02d}",
                        f,
                        variant=kind,
                        tags=[kind],
                    )
                )
    return cases


def build_inconsistent(domain, rng):
    specs = SCA_CONFLICTS if domain == "sca" else SAST_CONFLICTS
    cases = []
    for n in range(N_INCONSISTENT):
        field, values, sources = specs[n % len(specs)]
        while True:
            f = _sample(domain, rng, _fid(domain, rng))
            g = dict(f)
            g[field] = Conflict(field, values, sources)
            # Pre-registered rule: only conflicts that change the rubric outcome.
            if reference_label(domain, g)["disposition"] == "REVIEW":
                break
        cases.append(
            make_case(
                domain,
                "inconsistent",
                f"{domain}-conflict-{n + 1:02d}",
                g,
                attribute=field,
                variant="conflict",
            )
        )
    return cases


def _pick_bases(main, rng, n, stratify_urgent=False):
    if not stratify_urgent:
        return rng.sample(main, n)
    urgent = [c for c in main if c["reference"]["urgent"]]
    calm = [c for c in main if c["reference"]["urgent"] is False]
    return rng.sample(urgent, n // 2) + rng.sample(calm, n - n // 2)


def build_missing(domain, main, rng):
    fields = SCA_MISSING_FIELDS if domain == "sca" else SAST_MISSING_FIELDS
    cases = []
    for b in _pick_bases(main, rng, N_MISSING_BASES):
        base = deserialize_facts(b["facts"])
        cases.append(
            make_case(
                domain,
                "missing",
                f"{b['case_id']}-known",
                base,
                group=b["case_id"],
                variant="known",
                anchor=b["case_id"],
            )
        )
        for field in fields:
            for mode, val in (("unknown", UNKNOWN), ("omitted", OMIT)):
                g = dict(base)
                g[field] = val
                cases.append(
                    make_case(
                        domain,
                        "missing",
                        f"{b['case_id']}-{field}-{mode}",
                        g,
                        group=b["case_id"],
                        attribute=field,
                        variant=mode,
                        anchor=b["case_id"],
                    )
                )
    return cases


def build_counterfactual(domain, rng):
    toggles = SCA_TOGGLES if domain == "sca" else SAST_TOGGLES
    cases = []
    for n in range(1, N_CF_CONTEXTS + 1):
        target = (n - 1) % 5  # stratify contexts across reference exposure levels
        while True:
            ctx = _sample(domain, rng, _fid(domain, rng))
            if reference_label(domain, ctx)["exposure"] == target:
                break
        for attr, lo, hi in toggles:
            for variant, val in (("low", lo), ("high", hi)):
                g = dict(ctx)
                g[attr] = val
                if domain == "sca" and g["kev"] and g["exploit"] == "none":
                    g["exploit"] = "weaponized"  # keep KEV/exploit consistent (see sampler)
                cases.append(
                    make_case(
                        domain,
                        "counterfactual",
                        f"{domain}-cf{n:02d}-{attr}-{variant}",
                        g,
                        group=f"{domain}-cf{n:02d}",
                        attribute=attr,
                        variant=variant,
                    )
                )
    return cases


def build_adversarial(domain, main, rng):
    cases = []
    for b in _pick_bases(main, rng, N_ADV_BASES, stratify_urgent=True):
        base = deserialize_facts(b["facts"])
        cases.append(
            make_case(
                domain,
                "adversarial",
                f"{b['case_id']}-adv-normal",
                base,
                group=b["case_id"],
                variant="normal",
                anchor=b["case_id"],
            )
        )
        for kind in ("inj_down", "inj_up", "argue_down"):
            cases.append(
                make_case(
                    domain,
                    "adversarial",
                    f"{b['case_id']}-adv-{kind}",
                    base,
                    group=b["case_id"],
                    variant=kind,
                    adversarial=kind,
                    anchor=b["case_id"],
                )
            )
    return cases


def build_paraphrase(domain, main, rng):
    cases = []
    for b in _pick_bases(main, rng, N_PARA_BASES):
        base = deserialize_facts(b["facts"])
        variants = [
            ("canonical", dict()),
            ("reworded_description", dict(description_variant="B")),
            ("alt_keys", dict(representation="alt_keys")),
            ("prose", dict(representation="prose")),
        ]
        for name, kw in variants:
            cases.append(
                make_case(
                    domain,
                    "paraphrase",
                    f"{b['case_id']}-para-{name}",
                    base,
                    group=b["case_id"],
                    variant=name,
                    anchor=b["case_id"],
                    **kw,
                )
            )
    return cases


def build_repeat(domain, main, rng):
    cases = []
    for b in _pick_bases(main, rng, N_REPEAT_BASES):
        base = deserialize_facts(b["facts"])
        for r in range(0, N_REPEATS + 1):
            cases.append(
                make_case(
                    domain,
                    "repeat",
                    f"{b['case_id']}-rep{r}",
                    base,
                    group=b["case_id"],
                    variant=f"rep{r}",
                    repeat=r,
                    anchor=b["case_id"],
                )
            )
    return cases


def build_domain(domain: str, seed: int = SEED) -> list[dict]:
    # Independent, fixed sub-seeds so adding one experiment never reshuffles another.
    def sub(name):
        return random.Random(f"{seed}-{domain}-{name}")

    main = build_main(domain, sub("main"))
    cases = list(main)
    cases += build_contradiction(domain, sub("contradiction"))
    cases += build_inconsistent(domain, sub("inconsistent"))
    cases += build_missing(domain, main, sub("missing"))
    cases += build_counterfactual(domain, sub("counterfactual"))
    cases += build_adversarial(domain, main, sub("adversarial"))
    cases += build_paraphrase(domain, main, sub("paraphrase"))
    cases += build_repeat(domain, main, sub("repeat"))
    return cases


def smoke_case() -> dict:
    """A single synthetic SCA case used only for the smoke test (not in the benchmark)."""
    f = _sca_random_facts(random.Random(f"{SEED}-smoke"), "OSV-000001")
    f.update(
        cvss=9.8,
        epss=0.004,
        kev=False,
        exploit="none",
        internet=False,
        reachable=False,
        asset="critical",
        control="none",
        environment="production",
    )
    return make_case("sca", "smoke", "sca-smoke-001", f)
