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

The package name `mcpvuln` is registered to this project; 0.2.0, 0.2.1 and 0.3.0 are
published. A version number can never be reused on PyPI, so treat an upload as final.

The container image and the release assets need no manual step: pushing a `v*` tag runs
`.github/workflows/release.yml`, which builds the image from `Dockerfile`, pushes it to
`ghcr.io/dinakar-s/mcpvuln` (GitHub Packages) with the version and `latest` tags, smoke
tests the pushed image, and attaches the sdist and wheel to the GitHub release.

The token lives in keywarden as `pypi/prod`, so the value never has to be handled
directly:

```bash
keywarden grant pypi/prod --exec python --ttl 15m
keywarden run --inject pypi/prod -- python benchmark/_publish.py --check dist/*
keywarden run --inject pypi/prod -- python benchmark/_publish.py dist/*
```

`benchmark/_publish.py` bridges keywarden's `API_TOKEN` to twine's `TWINE_PASSWORD`
inside the child process, and `--check` validates the token shape and the artifact list
without uploading. Run the check first: it catches a token pasted without its `pypi-`
prefix, which is otherwise a wasted authentication attempt.

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

Both post-upload README edits are done: the "not on PyPI yet" note is removed and the
version and downloads badges are in place.

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
