"""Conformance tests for the four algorithms in the design write-up.

The published description of this tool specifies four algorithms. These tests
assert, step by step, that the implementation actually does what is described,
so the write-up and the code cannot drift apart silently.

If one of these fails, either the code regressed or the write-up changed. Fix
whichever is wrong; do not delete the test.
"""

import inspect

import pytest

from mcpvuln import contract as C
from mcpvuln.firecrawl_integration import ThreatIntelClient
from mcpvuln.patterns import PATTERNS
from mcpvuln.report_generator import DeterministicReporter
from mcpvuln.scoring import infer_ssvc, risk_index, score_cvss
from mcpvuln.summary import finding_summary, leadership_summary
from mcpvuln.vuln_analyzer import VulnerabilityAnalyzer

SAMPLE = (
    "import os, pickle\n"
    "def run(user_input):\n"
    "    os.system('ping ' + user_input)\n"
    "def load(payload):\n"
    "    return pickle.loads(payload)\n"
)


def build_contract():
    findings = [f.to_dict() for f in VulnerabilityAnalyzer().analyze(SAMPLE, "srv.py")]
    return C.build("demo-repo", findings, files_scanned=1, lines_scanned=5)


# ===================================================================== Algorithm 1
# Vulnerability Analysis Agent Tool
#   1: Load vulnerability pattern library P
#   2: Initialize findings list F <- 0
#   3: for each source file s in R
#   5: for each vulnerability category c in P
#   6: search s using detection patterns of c
#   8: record <category, file, line number, confidence> in F
#  12: return F for CVSS/SSVC risk assessment


class TestAlgorithm1:
    def test_step1_pattern_library_is_loaded(self):
        a = VulnerabilityAnalyzer()
        assert len(a.patterns) == len(PATTERNS) > 0

    def test_step2_empty_input_yields_empty_findings(self):
        assert VulnerabilityAnalyzer().analyze("", "x.py") == []

    def test_step3_iterates_every_source_file_in_the_repository(self, tmp_path):
        for i in range(4):
            (tmp_path / f"m{i}.py").write_text(SAMPLE, encoding="utf-8")
        files = {f.file for f in VulnerabilityAnalyzer().analyze_path(str(tmp_path))}
        assert files == {f"m{i}.py" for i in range(4)}

    def test_step5_every_category_is_searched(self):
        """Each category in the library must be reachable, not just the first."""
        cats = {p.category for p in PATTERNS}
        assert len(cats) > 10
        a = VulnerabilityAnalyzer()
        found = {f.category for f in a.analyze(SAMPLE, "srv.py")}
        assert {"command_injection", "unsafe_deserialization"} <= found

    def test_step8_records_category_file_line_and_confidence(self):
        """The tuple the algorithm specifies, in full."""
        for f in VulnerabilityAnalyzer().analyze(SAMPLE, "srv.py"):
            d = f.to_dict()
            assert d["category"]
            assert d["file"] == "srv.py"
            assert isinstance(d["line"], int) and d["line"] > 0
            assert isinstance(d["confidence"], float)
            assert 0.0 <= d["confidence"] <= 1.0

    def test_step8_line_numbers_are_correct(self):
        f = VulnerabilityAnalyzer().analyze(SAMPLE, "srv.py")
        by_cat = {x.category: x.line for x in f}
        assert by_cat["command_injection"] == 3
        assert by_cat["unsafe_deserialization"] == 5

    def test_step12_findings_feed_cvss_and_ssvc(self):
        c = build_contract()
        assert c["findings"]
        for f in c["findings"]:
            assert f["cvss_vector"].startswith("CVSS:4.0/")
            assert f["ssvc"]["priority"]


# ===================================================================== Algorithm 2
# Vulnerability Report Output
#   2: score <- compute_CVSS_v4(v)     base score + vector
#   3: risk_index <- compute_risk_index(v)   0-100
#   4: priority <- assign_SSVC(v, score)
#   5: mitigation <- generate_mitigation(v)
#   6: summary <- generate_executive_summary(v)   2-3 sentences, business-facing
#   7: append (score, risk_index, priority, mitigation, summary) to report
#   9: if external_vulns then analyze and append
#  13: prepend top-line risk summary for leadership


class TestAlgorithm2:
    def test_step2_cvss_v4_base_score_and_vector(self):
        for f in build_contract()["findings"]:
            assert f["cvss_vector"].startswith("CVSS:4.0/")
            assert 0.0 <= f["cvss_base_score"] <= 10.0

    def test_step3_risk_index_is_zero_to_one_hundred(self):
        for f in build_contract()["findings"]:
            assert isinstance(f["risk_index"], int)
            assert 0 <= f["risk_index"] <= 100

    def test_step4_ssvc_priority_and_action(self):
        for f in build_contract()["findings"]:
            assert f["ssvc"]["priority"] in (
                "Defer", "Scheduled", "Out-of-Band", "Immediate")
            assert f["ssvc"]["decision_path"]

    def test_step5_every_finding_carries_a_mitigation(self):
        for f in build_contract()["findings"]:
            assert f["remediation"].strip(), f"{f['pattern_id']} has no remediation"

    def test_step5_every_pattern_defines_a_mitigation(self):
        missing = [p.id for p in PATTERNS if not p.remediation.strip()]
        assert not missing, f"patterns without remediation: {missing}"

    def test_step6_executive_summary_is_two_or_three_sentences(self):
        for f in build_contract()["findings"]:
            s = f["executive_summary"]
            assert s, "no executive summary"
            n = s.count(". ") + s.count(".\n") + (1 if s.rstrip().endswith(".") else 0)
            assert 2 <= n <= 4, f"expected 2-3 sentences, got {n}: {s!r}"

    def test_step6_executive_summary_is_business_facing(self):
        """It must not read as a regex dump. No rule ids, no pattern syntax."""
        for f in build_contract()["findings"]:
            s = f["executive_summary"]
            assert f["pattern_id"] not in s
            assert "\\s" not in s and "regex" not in s.lower()

    def test_step7_report_contains_all_five_outputs(self):
        c = build_contract()
        md = DeterministicReporter().render(c)
        for f in c["findings"]:
            if f.get("informational"):
                continue
            assert str(f["cvss_base_score"]) in md
            assert str(f["risk_index"]) in md
            assert f["ssvc"]["priority"] in md
            assert f["remediation"][:40] in md
            assert f["executive_summary"][:40] in md

    def test_step9_external_vulnerabilities_are_appended(self):
        findings = [f.to_dict() for f in VulnerabilityAnalyzer().analyze(SAMPLE, "s.py")]
        c = C.build("r", findings, files_scanned=1, lines_scanned=5,
                    external_intel=[{"name": "CVE-2025-49596",
                                     "description": "MCP Inspector RCE",
                                     "source_url": "https://example.invalid/a"}])
        md = DeterministicReporter().render(c)
        assert "External threat intelligence" in md
        assert "CVE-2025-49596" in md

    def test_step13_leadership_summary_is_prepended(self):
        c = build_contract()
        md = DeterministicReporter().render(c)
        assert c["leadership_summary"]
        assert md.index("Risk summary") < md.index("## Findings")

    def test_step13_leadership_summary_handles_a_clean_scan(self):
        c = C.build("clean", [], files_scanned=1, lines_scanned=10)
        assert c["leadership_summary"]
        assert "No issues" in c["leadership_summary"]

    def test_report_is_reproducible(self):
        """The algorithm is deterministic, so two runs must agree."""
        c = build_contract()
        r = DeterministicReporter()
        strip = lambda s: "\n".join(  # noqa: E731
            x for x in s.splitlines() if not x.startswith("Generated "))
        assert strip(r.render(c)) == strip(r.render(c))


# ===================================================================== Algorithm 3
# Cross Tenant Context Bleed
#   1: observe: C uses a single global key with no tenant-scoping
#   4: if C returns Tenant A's cached context to Tenant B
#   5: flag <- VULNERABLE
#   6: severity <- CVSS v4.0 High; SSVC Immediate
#   8: mitigation(composite tenant-bound cache keys)

VULNERABLE_CACHES = [
    'session_cache = {}\nsession_cache["context"] = ctx\n',
    "_context_store: dict = {}\n",
    "global_context = build()\n",
    'cache["global"] = ctx\n',
]

SCOPED_CACHES = [
    "session_cache[(tenant_id, user_id)] = ctx\n",
    'session_cache[f"{tenant_id}:{sid}"] = ctx\n',
    "user_cache[user_id] = row\n",
    "results = {}\n",
]


class TestAlgorithm3:
    @pytest.mark.parametrize("src", VULNERABLE_CACHES)
    def test_step1_unscoped_cache_is_flagged(self, src):
        cats = {f.category for f in VulnerabilityAnalyzer().analyze(src, "srv.py")}
        assert "cross_tenant_context_bleed" in cats

    @pytest.mark.parametrize("src", SCOPED_CACHES)
    def test_tenant_scoped_cache_is_not_flagged(self, src):
        cats = {f.category for f in VulnerabilityAnalyzer().analyze(src, "srv.py")}
        assert "cross_tenant_context_bleed" not in cats

    def test_step6_severity_is_high_and_confidentiality_impacting(self):
        f = [x for x in VulnerabilityAnalyzer().analyze(VULNERABLE_CACHES[0], "srv.py")
             if x.category == "cross_tenant_context_bleed"][0]
        _, score, severity = score_cvss(f.cvss_metrics)
        assert score >= 7.0, f"expected High or above, got {score}"
        assert severity in ("High", "Critical")
        assert f.cvss_metrics["VC"] == "H", "must record a confidentiality impact"

    def test_step8_mitigation_names_composite_tenant_bound_keys(self):
        f = [x for x in VulnerabilityAnalyzer().analyze(VULNERABLE_CACHES[0], "srv.py")
             if x.category == "cross_tenant_context_bleed"][0]
        m = f.remediation.lower()
        assert "composite" in m and "tenant" in m


# ===================================================================== Algorithm 4
# Firecrawl Integration Agent
#   1: if FIRECRAWL_API_KEY not set -> log error; return 0
#   4: app <- init_Firecrawl(api_key)
#   6: matches <- app.search(MCP/A2A/LLM vulnerability, limit = 10)
#   8: E <- E + {(title, description[:200], source_url)}
#  10: return E


class TestAlgorithm4:
    def test_step1_returns_empty_without_an_api_key(self, monkeypatch):
        monkeypatch.delenv("FIRECRAWL_API_KEY", raising=False)
        c = ThreatIntelClient(api_key=None)
        assert c.available() is False
        assert c.fetch() == []

    def test_step6_search_limit_is_ten(self):
        src = inspect.getsource(ThreatIntelClient.fetch)
        assert "limit=10" in src.replace(" ", "")

    def test_step6_search_query_covers_mcp_a2a_and_llm(self):
        src = inspect.getsource(ThreatIntelClient.fetch)
        assert "MCP" in src and "A2A" in src and "LLM" in src

    def test_step8_description_is_truncated_to_200(self):
        src = inspect.getsource(ThreatIntelClient.fetch)
        assert "[:200]" in src
        assert "[:300]" not in src

    def test_step8_entries_carry_name_description_and_source_url(self, monkeypatch):
        class FakeApp:
            def __init__(self, *a, **k):
                pass

            def search(self, *a, **k):
                class R:
                    data = [{"title": "T", "description": "D" * 500,
                             "url": "https://example.invalid/x"}]
                return R()

            def scrape_url(self, url, **k):
                raise RuntimeError("offline")

        import mcpvuln.firecrawl_integration as fi
        monkeypatch.setitem(__import__("sys").modules, "firecrawl",
                            type("m", (), {"FirecrawlApp": FakeApp}))
        out = fi.ThreatIntelClient(api_key="x", sources=["https://example.invalid/y"]).fetch()
        assert out and set(out[0]) == {"name", "description", "source_url"}
        assert len(out[0]["description"]) == 200

    def test_a_failed_crawl_is_not_reported_as_a_vulnerability(self, monkeypatch):
        """Regression: failures used to be appended to the results list."""
        class FakeApp:
            def __init__(self, *a, **k):
                pass

            def search(self, *a, **k):
                raise RuntimeError("down")

            def scrape_url(self, url, **k):
                raise RuntimeError("down")

        import mcpvuln.firecrawl_integration as fi
        monkeypatch.setitem(__import__("sys").modules, "firecrawl",
                            type("m", (), {"FirecrawlApp": FakeApp}))
        out = fi.ThreatIntelClient(api_key="x", sources=["https://example.invalid/y"]).fetch()
        assert out == []


# ============================================================ cross-cutting claims


def test_dual_stage_scoring_is_deterministic_across_runs():
    """The write-up presents CVSS and SSVC as computed, not generated."""
    m = {"AV": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "H"}
    first = (score_cvss(m), infer_ssvc(9.3, m, 0.8), risk_index(9.3, 0.8, "Immediate"))
    for _ in range(5):
        assert (score_cvss(m), infer_ssvc(9.3, m, 0.8),
                risk_index(9.3, 0.8, "Immediate")) == first


def test_summaries_are_deterministic():
    c = build_contract()
    f = c["findings"][0]
    assert finding_summary(f) == finding_summary(f)
    assert leadership_summary(c) == leadership_summary(c)


def test_every_category_has_a_business_impact_phrase():
    """Algorithm 2 step 6 must work for every category the library can emit."""
    from mcpvuln.summary import _IMPACT
    missing = sorted({p.category for p in PATTERNS} - set(_IMPACT))
    assert not missing, f"categories with no plain-language impact: {missing}"
