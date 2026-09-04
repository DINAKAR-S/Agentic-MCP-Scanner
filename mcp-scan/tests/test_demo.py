"""The demo pair is a contract with the reader, so it is tested like one.

``demo/vulnerable`` and ``demo/safe`` are the same server twice, with every issue
fixed in the second. If the vulnerable half stops producing findings the rules
have regressed; if the safe half starts producing them the rules have got noisy.
Either way the README's numbers would be wrong, which is worse than a failing test.
"""

import os

import pytest

from mcpvuln.vuln_analyzer import VulnerabilityAnalyzer

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "demo")
VULNERABLE = os.path.join(DEMO, "vulnerable")
SAFE = os.path.join(DEMO, "safe")

pytestmark = pytest.mark.skipif(
    not os.path.isdir(VULNERABLE), reason="demo fixtures not present")


def scan(path):
    return VulnerabilityAnalyzer().analyze_path(path)


def reportable(path):
    return [f for f in scan(path) if not f.informational]


# ------------------------------------------------------------------ the fixed half

def test_the_fixed_server_produces_no_reportable_findings():
    """The half that matters. A scanner that fires on correct code is not measuring."""
    found = reportable(SAFE)
    assert found == [], "\n".join(
        f"  {f.category} {f.file}:{f.line}  {f.code[:70]}" for f in found)


# ------------------------------------------------------------- the vulnerable half

EXPECTED_CATEGORIES = {
    # MCP layer
    "identity_trust_forgery",
    "audit_integrity",
    "container_escape",
    "supply_chain",
    "cross_tenant_context_bleed",
    # Agentic AI layer
    "excessive_agency",
    "cross_agent_memory",
    # LLM layer
    "prompt_injection",
    # Traditional web
    "sql_injection",
    "command_injection",
    "hardcoded_secrets",
    "unsafe_deserialization",
}


@pytest.mark.parametrize("category", sorted(EXPECTED_CATEGORIES))
def test_each_planted_vulnerability_is_detected(category):
    assert category in {f.category for f in reportable(VULNERABLE)}


def test_all_four_taxonomy_layers_are_exercised():
    layers = {f.layer for f in reportable(VULNERABLE)}
    assert layers == {"MCP", "Agentic AI", "LLM", "Traditional Web"}


def test_the_readme_finding_count_is_accurate():
    """demo/README.md promises a number. Keep it true."""
    assert len(reportable(VULNERABLE)) == 20


def test_the_readme_category_count_is_accurate():
    assert len({f.category for f in reportable(VULNERABLE)}) == 12


# ------------------------------------------------------------------- the comparison

def test_the_pair_discriminates():
    """The whole point of shipping both halves."""
    assert len(reportable(VULNERABLE)) > 15
    assert len(reportable(SAFE)) == 0


def test_both_halves_define_the_same_functions():
    """If the two drift apart, the comparison stops being fair."""
    import ast

    for filename in ("server.py", "identity.py", "agent.py"):
        names = []
        for root in (VULNERABLE, SAFE):
            src = open(os.path.join(root, filename), encoding="utf-8").read()
            tree = ast.parse(src)
            names.append({n.name for n in ast.walk(tree)
                          if isinstance(n, ast.FunctionDef)})
        only_vulnerable = names[0] - names[1]
        assert not only_vulnerable, (
            f"{filename}: {sorted(only_vulnerable)} exist only in the vulnerable half, "
            f"so the two are not the same server any more")
