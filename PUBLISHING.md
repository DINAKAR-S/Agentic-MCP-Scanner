# Publishing

Maintainer notes. Nothing here is needed to use the tool.

## Before publishing anything

```bash
cd mcp-scan
pytest tests/ -q                                  # 140 tests
ruff check mcpvuln benchmark tests
mcpvuln --self-check
python benchmark/run_benchmark.py                 # must stay at or under 0.05 per 100 LOC
mcpvuln ../demo/vulnerable                        # expect 20 reportable
mcpvuln ../demo/safe                              # expect 0
```

CI enforces all of this, so a green build on `main` is the same check.

## PyPI

The package name `mcpvuln` is registered to this project. A version number can never be
reused on PyPI, so treat an upload as final.

```bash
cd mcp-scan
rm -rf dist build *.egg-info
python -m build                    # produces the wheel and the sdist
python -m twine check dist/*       # both must report PASSED
```

Test on TestPyPI first if the packaging changed:

```bash
python -m twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ --no-deps mcpvuln
```

Then publish:

```bash
python -m twine upload dist/*
# username: __token__
# password: the pypi-... API token
```

Get a token at <https://pypi.org/manage/account/token/>. Scope it to this project once
the project exists; the first upload needs an account-wide token. Store it in
`~/.pypirc` or as `TWINE_PASSWORD`, and never commit it.

After the first successful upload:

1. Delete the "Not on PyPI yet" note from the README Install section.
2. Add the downloads badge to the README:
   `[![PyPI](https://img.shields.io/pypi/v/mcpvuln)](https://pypi.org/project/mcpvuln/)`
   `[![Downloads](https://img.shields.io/pypi/dm/mcpvuln)](https://pypi.org/project/mcpvuln/)`

## GitHub release

```bash
git tag -a vX.Y.Z -m "short description"
git push origin vX.Y.Z
gh release create vX.Y.Z --title "..." --notes-file notes.md --latest
gh release upload vX.Y.Z mcp-scan/dist/* --clobber
```

Attach the wheel and the sdist, so the tool is installable without PyPI.

## Version bump checklist

`mcp-scan/mcpvuln/__init__.py` (`__version__`), `mcp-scan/setup.py` (`version`),
`CITATION.cff` (`version` and `date-released`), and a new `CHANGELOG.md` section. The
README's test-count and false-positive badges are hand-written, so check them too.
