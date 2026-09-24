"""Offline tests: rubric, baselines, rendering hygiene, dataset integrity, client secrecy."""

import json
from pathlib import Path

import pytest

from jev_security import datasets as D
from jev_security.baseline import context_points, severity_only
from jev_security.client import DecisionsClient
from jev_security.reference import reference_label
from jev_security.render import render
from jev_security.schemas import OMIT, UNKNOWN, Conflict

ROOT = Path(__file__).resolve().parents[1]


def _sca(**kw):
    f = {
        "finding_id": "OSV-1",
        "package": "p",
        "version": "1.0.0",
        "vuln_class": "x",
        "function": "f",
        "service": "svc-a",
        "cvss": 9.8,
        "epss": 0.004,
        "kev": False,
        "exploit": "none",
        "internet": False,
        "reachable": False,
        "asset": "critical",
        "sensitive": False,
        "privileges": "none",
        "complexity": "low",
        "fix": True,
        "control": "none",
        "dependency": "direct",
        "environment": "production",
    }
    f.update(kw)
    return f


def _sast(**kw):
    f = D._sast_random_facts(__import__("random").Random(1), "SAST-1")
    f.update(
        dict(
            severity="CRITICAL",
            attacker_controlled=True,
            reachable=True,
            sanitization="none",
            auth="none",
            internet=True,
            privilege="standard",
            sensitive=True,
            preconditions="none",
            asset="critical",
            control="none",
            environment="production",
        )
    )
    f.update(kw)
    return f


def test_high_cvss_low_context_is_low_priority():
    r = reference_label("sca", _sca(asset="low", control="effective"))
    assert r["disposition"] == "DEFER" and r["urgent"] is False


def test_moderate_cvss_high_context_is_urgent():
    r = reference_label(
        "sca",
        _sca(
            cvss=6.5, epss=0.72, kev=True, exploit="weaponized", internet=True, reachable=True, sensitive=True
        ),
    )
    assert r["disposition"] in ("ACCELERATED", "EMERGENCY") and r["urgent"] is True


def test_sast_unreachable_critical_is_not_urgent():
    assert reference_label("sast", _sast(reachable=False))["urgent"] is False
    assert reference_label("sast", _sast(environment="test_code"))["disposition"] == "DEFER"


def test_sast_medium_but_exploitable_is_urgent():
    assert reference_label("sast", _sast(severity="MEDIUM"))["urgent"] is True


def test_unknown_decision_relevant_field_gives_review():
    f = _sca(cvss=7.5, internet=True, reachable=UNKNOWN, kev=True, exploit="weaponized")
    assert reference_label("sca", f)["disposition"] == "REVIEW"


def test_unknown_irrelevant_field_stays_determinate():
    # Unreachable gate makes EPSS irrelevant; low asset + effective control keeps it DEFER.
    f = _sca(epss=UNKNOWN, asset="low")
    assert reference_label("sca", f)["disposition"] == "DEFER"


def test_conflict_enumerates_only_asserted_values():
    f = _sca(
        reachable=Conflict("reachable", (False, True), ("a", "b")),
        internet=True,
        kev=True,
        exploit="weaponized",
    )
    assert reference_label("sca", f)["n_completions"] == 2


def test_baselines_basic():
    assert severity_only("sca", _sca())["disposition"] == "EMERGENCY"
    assert context_points("sca", _sca())["disposition"] in ("DEFER", "STANDARD")


def test_render_unknown_and_omit():
    s = render("sca", _sca(reachable=UNKNOWN, epss=OMIT))
    assert s["vulnerable_function_reachable"] == "unknown"
    assert "epss_probability" not in s and "epss_band" not in s


FORBIDDEN_IN_STATE = [
    "contradiction",
    "counterfactual",
    "inconsistent",
    "paraphrase",
    "reference",
    "high_severity",
    "low_severity",
    "HIGH_RISK",
    "sca-main",
    "sast-main",
    "anchor",
    "rubric",
    "expected",
]


@pytest.fixture(scope="module")
def all_cases():
    out = []
    for d in ("sca", "sast"):
        p = ROOT / f"data/{d}_cases.json"
        out += json.loads(p.read_text())["cases"] if p.exists() else D.build_domain(d)
    return out


def test_no_labels_leak_into_state(all_cases):
    for c in all_cases:
        blob = json.dumps(c["state"])
        for word in FORBIDDEN_IN_STATE:
            assert word not in blob, (c["case_id"], word)
        if c["render"]["adversarial"] is None:
            for word in ("DEFER", "EMERGENCY", "ACCELERATED", "REVIEW", "SYSTEM INSTRUCTION"):
                assert word not in blob, (c["case_id"], word)


def test_stored_reference_labels_recompute(all_cases):
    for c in all_cases:
        assert reference_label(c["domain"], D.deserialize_facts(c["facts"])) == c["reference"]


def test_counterfactual_pairs_differ_in_one_attribute(all_cases):
    cf = [c for c in all_cases if c["experiment"] == "counterfactual"]
    by = {}
    for c in cf:
        by.setdefault((c["group"], c["attribute"]), {})[c["variant"]] = c
    assert len(by) == 2 * D.N_CF_CONTEXTS * 7
    for (_, attr), pair in by.items():
        lo, hi = pair["low"]["facts"], pair["high"]["facts"]
        diff = {k for k in lo if lo[k] != hi[k]}
        assert attr in diff
        assert diff <= {attr, "exploit"}  # KEV/exploit consistency coupling only


def test_adversarial_and_paraphrase_keep_facts(all_cases):
    for exp in ("adversarial", "paraphrase", "repeat"):
        groups = {}
        for c in all_cases:
            if c["experiment"] == exp:
                groups.setdefault(c["group"], []).append(json.dumps(c["facts"], sort_keys=True))
        for facts in groups.values():
            assert len(set(facts)) == 1


def test_client_never_exposes_key(tmp_path, monkeypatch):
    secret = "sk-or-test-SECRET-123"

    class FakeResp:
        status_code = 200
        ok = True
        headers = {"content-type": "application/json", "set-cookie": "x"}
        text = "{}"

        def json(self):
            return {"answers": {}, "usage": {"input_tokens": 1, "output_tokens": 1}}

    client = DecisionsClient(secret)
    monkeypatch.setattr(client._session, "post", lambda *a, **k: FakeResp())
    rec = client.decide({"model": "m", "state": "s", "questions": {}}, tmp_path, "k1")
    assert secret not in repr(client)
    assert secret not in json.dumps(rec)
    assert secret not in (tmp_path / "k1__a1.json").read_text()
    assert "set-cookie" not in rec["response_headers"]
    with pytest.raises(FileExistsError):  # raw records are write-once
        client.decide({"model": "m", "state": "s", "questions": {}}, tmp_path, "k1")
