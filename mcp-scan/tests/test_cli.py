"""CLI contract."""


from mcpvuln.cli import main


def test_self_check_passes():
    assert main(["--self-check"]) == 0


def test_no_args_prints_help(capsys):
    assert main([]) == 2


def test_offline_scan_of_a_directory(tmp_path):
    (tmp_path / "app.py").write_text("import os\nos.system('ping ' + h)\n", encoding="utf-8")
    out = tmp_path / "out"
    rc = main([str(tmp_path), "--out", str(out), "--json", str(out / "c.json"), "-q"])
    assert rc == 0
    assert (out / "c.json").exists()
    assert any(p.name.endswith("_security_report.md") for p in out.iterdir())


def test_scan_needs_no_api_keys(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("FIRECRAWL_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert main([str(tmp_path), "--out", str(tmp_path / "o"), "-q"]) == 0


def test_fail_on_returns_nonzero(tmp_path):
    (tmp_path / "bad.py").write_text(
        "import os\nos.system('ping ' + host)\n", encoding="utf-8")
    rc = main([str(tmp_path), "--out", str(tmp_path / "o"), "--fail-on", "high", "-q"])
    assert rc == 3


def test_fail_on_clean_repo_returns_zero(tmp_path):
    (tmp_path / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    rc = main([str(tmp_path), "--out", str(tmp_path / "o"), "--fail-on", "high", "-q"])
    assert rc == 0
