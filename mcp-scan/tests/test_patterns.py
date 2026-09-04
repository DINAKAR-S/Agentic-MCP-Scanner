"""The pattern set must stay healthy. These tests encode defects we actually shipped."""

import re

import pytest

from mcpvuln.patterns import PATTERNS, LAYER_LLM, LAYER_AGENT, LAYER_MCP, LAYER_WEB, validate


def test_pattern_set_is_valid():
    problems = validate()
    assert problems == [], "pattern set invalid:\n" + "\n".join(problems)


def test_no_duplicate_ids():
    ids = [p.id for p in PATTERNS]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate pattern ids silently overwrite each other: {dupes}"


def test_every_regex_compiles():
    for p in PATTERNS:
        p.compiled()


def test_shell_pipes_are_escaped():
    """Regression: `wget .* | sh` read '|' as alternation, so ' sh' matched 'should'.

    That single typo produced 2,061 of 3,642 findings on clean official MCP code.
    """
    for p in PATTERNS:
        if re.search(r"\b(?:curl|wget)\b", p.regex):
            assert r"\|" in p.regex, (
                f"{p.id}: shell pipeline pattern must escape '|'; "
                f"unescaped it is regex alternation"
            )


def test_no_bare_substring_patterns():
    """Regression: patterns like 'latest' and 'http://' fired on any occurrence."""
    bare = re.compile(r"^[A-Za-z_][A-Za-z0-9_ .:/-]*$")
    offenders = [p.id for p in PATTERNS if bare.match(p.regex)]
    assert not offenders, f"unanchored bare-substring patterns: {offenders}"


def test_layers_are_known():
    allowed = {LAYER_LLM, LAYER_AGENT, LAYER_MCP, LAYER_WEB}
    for p in PATTERNS:
        assert p.layer in allowed, f"{p.id}: unknown layer {p.layer!r}"


def test_confidence_in_range():
    for p in PATTERNS:
        assert 0.0 <= p.confidence <= 1.0, f"{p.id}: confidence {p.confidence}"


def test_ignorecase_is_opt_in_not_global():
    """Regression: global IGNORECASE made `DES\s*\(` match `includes(`."""
    for p in PATTERNS:
        if p.ignorecase and re.search(r"\b(?:DES|RC4|MD5|SHA)\b", p.regex):
            pytest.fail(f"{p.id}: crypto-algorithm pattern must be case-sensitive")
