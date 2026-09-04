"""Reporting must be complete and reproducible."""

from mcpvuln import contract as C
from mcpvuln.report_generator import DeterministicReporter, NarrativeReporter
from mcpvuln.vuln_analyzer import VulnerabilityAnalyzer


def contract_with(n_files=1):
    src = "import os\nos.system('ping ' + h)\nimport pickle\nd = pickle.loads(x)\n"
    findings = []
    for i in range(n_files):
        findings += [f.to_dict() for f in
                     VulnerabilityAnalyzer().analyze(src, f"mod{i}.py")]
    return C.build("repo", findings, files_scanned=n_files, lines_scanned=4 * n_files)


def test_report_renders():
    md = DeterministicReporter().render(contract_with())
    assert "# Security report" in md and "CVSS v4.0" in md


def test_report_is_byte_identical_across_runs():
    c = contract_with()
    assert DeterministicReporter().render(c) == DeterministicReporter().render(c)


def test_no_finding_is_silently_truncated():
    """Regression: the previous reporter passed findings[:20] and dropped the rest."""
    c = contract_with(n_files=60)
    reportable = [f for f in c["findings"] if not f.get("informational")]
    assert len(reportable) > 20, "need more than 20 findings to exercise this"
    md = DeterministicReporter().render(c)
    for f in reportable:
        assert f["file"] in md, f"{f['file']} missing from report"


def test_empty_contract_renders_cleanly():
    md = DeterministicReporter().render(C.build("empty", []))
    assert "No findings above the reporting confidence threshold" in md


def test_narrative_without_key_degrades_gracefully():
    out = NarrativeReporter(api_key=None).render(contract_with())
    assert "Skipped" in out


def test_narrative_failure_does_not_discard_a_completed_scan(monkeypatch):
    """Regression: an invalid API key raised straight out of render(), throwing
    away a scan that had already succeeded."""
    r = NarrativeReporter(api_key="deliberately-invalid")

    class Boom:
        def generate_content(self, *a, **k):
            raise RuntimeError("API key not valid")

    monkeypatch.setattr(r, "_client", lambda: Boom())
    out = r.render(contract_with())
    assert "Analyst narrative" in out
    assert "could not be generated" in out


def test_narrative_client_init_failure_is_contained(monkeypatch):
    r = NarrativeReporter(api_key="deliberately-invalid")

    def boom():
        raise RuntimeError("no network")

    monkeypatch.setattr(r, "_client", boom)
    out = r.render(contract_with())
    assert "Unavailable" in out
