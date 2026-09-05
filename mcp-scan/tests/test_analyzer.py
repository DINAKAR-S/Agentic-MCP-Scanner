"""Detection behaviour: what must be found, and what must not be."""

import textwrap

from mcpvuln.vuln_analyzer import VulnerabilityAnalyzer, context_weight


def cats(findings):
    return {f.category for f in findings}


def scan(src, path="app.py", **kw):
    return VulnerabilityAnalyzer(**kw).analyze(textwrap.dedent(src), path)


# ---------------------------------------------------------------- true positives

def test_detects_command_injection():
    f = scan("""
        import os
        def run(user_input):
            os.system("ping " + user_input)
    """)
    assert "command_injection" in cats(f)


def test_detects_sql_injection():
    f = scan("""
        def lookup(cur, name):
            cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    """)
    assert "sql_injection" in cats(f)


def test_detects_jwt_verification_disabled():
    f = scan("""
        import jwt
        def decode_token(tok):
            return jwt.decode(tok, key, options={"verify_signature": False})
    """)
    assert "identity_trust_forgery" in cats(f)


def test_detects_privileged_container():
    f = scan('services: {"agent": {"privileged": True}}\n', path="compose.yml")
    assert "container_escape" in cats(f)


def test_detects_docker_socket_mount():
    f = scan('volumes = ["/var/run/docker.sock:/var/run/docker.sock"]\n')
    assert "container_escape" in cats(f)


def test_detects_real_pipe_to_shell():
    f = scan('subprocess.run("curl https://x.sh | bash", shell=True)\n')
    assert "supply_chain" in cats(f)


def test_detects_unsafe_deserialization():
    f = scan("import pickle\ndata = pickle.loads(payload)\n")
    assert "unsafe_deserialization" in cats(f)


def test_detects_audit_log_deletion():
    f = scan('cur.execute("DELETE FROM audit_logs WHERE id = ?", (i,))\n')
    assert "audit_integrity" in cats(f)


# ---------------------------------------------------------------- false positives
# Each of these was an actual false positive measured against the official MCP
# reference implementations. They must stay silent.

def test_the_word_should_is_not_a_supply_chain_attack():
    f = scan("# Tests should be fast and deterministic\n")
    assert "supply_chain" not in cats(f)


def test_import_shutil_is_not_a_supply_chain_attack():
    f = scan("import shutil\n")
    assert "supply_chain" not in cats(f)


def test_includes_is_not_weak_cryptography():
    f = scan("const ok = comments.find(c => c.body.includes(marker));\n", path="a.js")
    assert "weak_crypto" not in cats(f)


def test_latest_in_a_docs_url_is_not_a_finding():
    f = scan("  - url: https://docs.pydantic.dev/latest/objects.inv\n", path="mkdocs.yml")
    assert "supply_chain" not in cats(f)


def test_localhost_http_is_not_rogue_server_impersonation():
    f = scan('allowed_origins = ["http://127.0.0.1:*", "http://localhost:*"]\n')
    assert "insecure_transport" not in cats(f)


def test_oauth_prose_in_documentation_is_not_a_finding():
    src = "A standard OAuth provider (**[OAuth clients](oauth-clients.md)**) asks first.\n"
    assert scan(src, path="docs/client/identity.md") == []


def test_while_true_event_loop_is_not_a_finding():
    f = scan("while True:\n    await queue.get()\n")
    assert f == [] or all(x.informational for x in f)


def test_code_pattern_inside_a_comment_is_suppressed():
    f = scan("""
        # os.system("rm -rf " + path)  <- do not do this
        pass
    """)
    assert "command_injection" not in cats(f)


def test_code_pattern_inside_a_docstring_is_suppressed():
    f = scan('''
        def helper():
            """Example: os.system("ping " + host) is unsafe."""
            return 1
    ''')
    assert "command_injection" not in cats(f)


# ---------------------------------------------------------------- behaviour

def test_findings_are_deduplicated_per_file_category_line():
    f = scan('os.system("a" + b); os.system("c" + d)\n')
    keys = [x.key() for x in f]
    assert len(keys) == len(set(keys))


def test_docs_paths_are_down_weighted():
    assert context_weight("docs/guide.md") < context_weight("src/app.py")
    assert context_weight("tests/test_app.py") < context_weight("src/app.py")
    assert context_weight("i18n/ja/pages/x.md") < context_weight("docs/guide.md") + 1


def test_findings_sorted_by_confidence_descending():
    f = scan("""
        import os, pickle
        os.system("x" + y)
        d = pickle.loads(z)
        t = "http://example.com/api"
    """)
    confs = [x.confidence for x in f]
    assert confs == sorted(confs, reverse=True)


def test_min_confidence_filters():
    src = 't = "http://prod-mcp.internal/api"\n'
    loose = scan(src, min_confidence=0.0)
    tight = scan(src, min_confidence=0.9)
    assert len(loose) > 0
    assert len(tight) < len(loose)


def test_reserved_and_fixture_hostnames_are_not_findings():
    """RFC 2606 names and common test fixtures are not production endpoints."""
    for host in ("http://example.com/x", "http://testserver/mcp",
                 "http://foo.example/x", "http://localhost:8000/mcp"):
        assert "insecure_transport" not in cats(scan('url = "%s"\n' % host)), host


def test_test_fixture_secrets_are_not_hardcoded_credentials():
    f = scan('client_secret = "test-client-secret-value"\n')
    assert "hardcoded_secrets" not in cats(f)


def test_re_search_is_not_an_unscoped_memory_query():
    """Regression: the memory-scoping rule matched Python's own re.search()."""
    f = scan("import re\nm = re.search(pattern, header)\n")
    assert "cross_agent_memory" not in cats(f)


def test_unscoped_vector_store_query_is_still_detected():
    f = scan("hits = memory_store.search(embedding, top_k=10)\n")
    assert "cross_agent_memory" in cats(f)


def test_empty_input_is_safe():
    assert VulnerabilityAnalyzer().analyze("", "empty.py") == []


def test_unparseable_python_does_not_crash():
    f = VulnerabilityAnalyzer().analyze("def broken(:\n  os.system('a'+b)\n", "b.py")
    assert isinstance(f, list)


def test_detection_is_deterministic():
    src = "import os\nos.system('ping ' + host)\n"
    a = VulnerabilityAnalyzer().analyze(src, "x.py")
    b = VulnerabilityAnalyzer().analyze(src, "x.py")
    assert [x.to_dict() for x in a] == [x.to_dict() for x in b]


# --------------------------------------------------------------- suppression

def test_ignore_file_directive_skips_whole_file():
    f = scan("""
        # mcpvuln: ignore-file
        import os
        os.system("ping " + host)
    """)
    assert f == []


def test_inline_ignore_directive_skips_that_line():
    f = scan("""
        import os
        os.system("a" + b)  # mcpvuln: ignore
        os.system("c" + d)
    """)
    assert [x.line for x in f] == [4]


def test_scoped_ignore_silences_only_the_named_rule():
    f = scan("""
        import os
        os.system("a" + b)  # mcpvuln: ignore[web.cmd_injection.os_system]
    """)
    assert f == []


def test_scoped_ignore_does_not_silence_other_rules():
    f = scan("""
        import os
        os.system("a" + b)  # mcpvuln: ignore[some.other.rule]
    """)
    assert "command_injection" in cats(f)


def test_pattern_module_does_not_flag_itself():
    """The rule definitions contain the literal strings the rules look for."""
    from mcpvuln import patterns as _p
    src = open(_p.__file__, encoding="utf-8").read()
    assert VulnerabilityAnalyzer().analyze(src, "mcpvuln/patterns.py") == []


# ------------------------------------------------- SQL injection outside Python
# Found by scanning a real TypeScript MCP server: the rule only matched Python's
# execute(), so db.query("SELECT ..." + x) was missed, and the memory-scoping rule
# claimed it instead and labelled it cross_agent_memory.

def test_js_sql_concatenation_is_sql_injection():
    f = scan('const rows = db.query("SELECT * FROM banks WHERE ifsc = \'" + code + "\'");\n',
             path="api.ts")
    assert "sql_injection" in cats(f)
    assert "cross_agent_memory" not in cats(f)


def test_js_template_literal_sql_is_sql_injection():
    f = scan("connection.query(`SELECT * FROM t WHERE id = ${id}`)\n", path="api.js")
    assert "sql_injection" in cats(f)


def test_parameterised_js_query_is_not_a_finding():
    f = scan('db.query("SELECT * FROM t WHERE id = ?", [id])\n', path="api.js")
    assert "sql_injection" not in cats(f)


def test_database_query_is_not_an_unscoped_memory_search():
    """db.query and pool.query are relational calls, not vector-store searches."""
    for src in ('db.query("SELECT 1")\n', 'pool.query("SELECT 1")\n'):
        assert "cross_agent_memory" not in cats(scan(src, path="api.js"))
