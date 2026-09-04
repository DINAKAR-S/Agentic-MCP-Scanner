"""The scan contract is the pipeline's stable interface."""

import json

from mcpvuln import contract as C
from mcpvuln.vuln_analyzer import VulnerabilityAnalyzer

SRC = "import os\nos.system('ping ' + host)\nimport pickle\nd = pickle.loads(x)\n"


def build():
    findings = [f.to_dict() for f in VulnerabilityAnalyzer().analyze(SRC, "app.py")]
    return C.build("test-repo", findings, files_scanned=1, lines_scanned=4)


def test_contract_validates():
    assert C.validate(build()) == []


def test_contract_is_json_serialisable():
    json.loads(C.dumps(build()))


def test_findings_carry_computed_scores():
    for f in build()["findings"]:
        assert f["cvss_vector"].startswith("CVSS:4.0/")
        assert isinstance(f["cvss_base_score"], float)
        assert f["ssvc"]["priority"] in ("Defer", "Scheduled", "Out-of-Band", "Immediate")


def test_findings_sorted_by_risk_descending():
    r = [f["risk_index"] for f in build()["findings"]]
    assert r == sorted(r, reverse=True)


def test_counts_add_up():
    c = build()
    s = c["scan"]
    assert s["findings_total"] == len(c["findings"])
    assert s["findings_reportable"] + s["findings_informational"] == s["findings_total"]


def test_empty_scan_is_valid():
    c = C.build("empty", [], files_scanned=0, lines_scanned=0)
    assert C.validate(c) == []
    assert c["scan"]["findings_total"] == 0


def test_roundtrip(tmp_path):
    c = build()
    p = C.save(c, str(tmp_path / "c.json"))
    assert C.load(p) == c
