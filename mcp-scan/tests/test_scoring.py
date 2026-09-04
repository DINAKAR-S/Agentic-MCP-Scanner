"""Scoring must be deterministic and spec-shaped."""

import pytest

from mcpvuln.scoring import (
    build_vector,
    infer_ssvc,
    risk_index,
    score_cvss,
    score_finding,
    severity_from_score,
    ssvc_decision,
)


def test_vector_is_wellformed():
    v = build_vector({"AV": "N", "VC": "H", "VI": "H", "VA": "H"})
    assert v.startswith("CVSS:4.0/")
    for m in ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"):
        assert f"{m}:" in v


def test_critical_rce_scores_critical():
    _, score, sev = score_cvss({"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                                "VC": "H", "VI": "H", "VA": "H"})
    assert score >= 9.0 and sev == "Critical"


def test_no_impact_scores_zero():
    _, score, sev = score_cvss({})
    assert score == 0.0 and sev == "None"


def test_scoring_is_deterministic():
    m = {"AV": "N", "PR": "L", "VC": "H", "VI": "H"}
    assert [score_cvss(m) for _ in range(5)].count(score_cvss(m)) == 5


def test_severity_bands():
    assert severity_from_score(0.0) == "None"
    assert severity_from_score(3.9) == "Low"
    assert severity_from_score(6.9) == "Medium"
    assert severity_from_score(8.9) == "High"
    assert severity_from_score(9.0) == "Critical"


def test_ssvc_immediate_when_active_and_high_mission():
    d = ssvc_decision("active", "yes", "total", "high")
    assert d["priority"] == "Immediate"


def test_ssvc_defer_when_nothing_applies():
    d = ssvc_decision("none", "no", "partial", "low")
    assert d["priority"] == "Defer"


def test_ssvc_rejects_bad_input():
    with pytest.raises(ValueError):
        ssvc_decision("someday", "no", "partial", "low")
    with pytest.raises(ValueError):
        ssvc_decision("none", "maybe", "partial", "low")


def test_static_findings_are_never_reported_as_actively_exploited():
    """A source scanner sees code, not exploitation in the wild."""
    for conf in (0.1, 0.5, 0.9, 1.0):
        d = infer_ssvc(9.8, {"VC": "H", "VI": "H", "VA": "H"}, conf)
        assert d["exploitation"] in ("none", "poc")


def test_risk_index_bounds_and_monotonicity():
    assert 0 <= risk_index(0.0, 0.0, "Defer") <= 100
    assert 0 <= risk_index(10.0, 1.0, "Immediate") <= 100
    assert risk_index(9.0, 0.9, "Immediate") > risk_index(3.0, 0.9, "Immediate")
    assert risk_index(9.0, 0.9, "Immediate") > risk_index(9.0, 0.2, "Immediate")


def test_score_finding_enriches_without_mutating():
    src = {"cvss_metrics": {"VC": "H", "VI": "H"}, "confidence": 0.8}
    out = score_finding(src)
    assert "cvss_vector" in out and "ssvc" in out and "risk_index" in out
    assert "cvss_vector" not in src


def test_malformed_metric_values_do_not_abort_a_scan():
    """Regression: an out-of-spec metric raised CVSS4MalformedError and killed the run."""
    vector, score, sev = score_cvss({"AV": "ZZZ", "not_a_metric": "x", "VC": "H", "VI": None})
    assert vector.startswith("CVSS:4.0/")
    assert isinstance(score, float)
    assert sev in ("None", "Low", "Medium", "High", "Critical")
    assert "AV:N" in vector, "an invalid value should fall back to the default"
    assert "VC:H" in vector, "valid metrics alongside an invalid one must survive"


def test_metric_values_are_case_insensitive():
    assert "VC:H" in build_vector({"VC": "h"})


def test_empty_metrics_scores_zero():
    _, score, sev = score_cvss({})
    assert score == 0.0 and sev == "None"
