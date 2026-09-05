# mcpvuln

[![CI](https://github.com/DINAKAR-S/Agentic-MCP-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/DINAKAR-S/Agentic-MCP-Scanner/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-140%20passing-brightgreen)](mcp-scan/tests)
[![False positives](https://img.shields.io/badge/false%20positives-0.008%20per%20100%20LOC-brightgreen)](mcp-scan/benchmark)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)

**A vulnerability scanner for MCP that proves how often it is wrong.**

MCP lets an agent discover and call tools at runtime, from servers somebody else
operates. That moves the unit of trust from a single function call to a whole protocol
session, and the failures that follow have no equivalent in ordinary application
security: forged agent identities, trust scores computed but never enforced, audit logs
that can be rewritten, one tenant's context served to another.

There are scanners already. What none of them ships is a way to tell how much of the
output is real. They are evaluated only against code known to be broken, so they can
measure what they catch but never what they invent. That is the part nobody tests,
because it requires scanning code that has nothing wrong with it and counting what comes
back. This one ships that corpus, and every precision number below is produced by running
against it.

> Status: 140 tests, CI on Linux and Windows across Python 3.9 to 3.12, and a build that
> fails if the false-positive rate on clean code rises above 0.05 per 100 lines. It
> currently sits at 0.008.

---

## The situation

You inherit an MCP server. It exposes eleven tools to an agent that can spend money, read the customer database and deploy containers. You want to know what is wrong with it before it ships.

So you run a scanner. It returns 3,283 findings.

You open the first one. It flags this line:

```
# Tests should be fast and deterministic
```

as a **malicious server supply chain attack**. The next flags `import shutil`. The next flags a documentation URL because it contains the word `latest`. By finding forty you stop reading, and the two real problems, a JWT decoded with `verify_signature: False` and a container mounting `docker.sock`, are somewhere in the remaining three thousand.

That is not a hypothetical. It is what version 0.1.0 of **this tool** did, measured against the official MCP Python SDK. One typo caused most of it: `wget .* | sh` treats `|` as regex alternation rather than a shell pipe, so the pattern matched the string `" sh"`, so it matched the word **"should"**, 1,852 times.

| Situation | Without a control corpus | With one |
|---|---|---|
| Scanner returns 3,000 findings | Sounds thorough | You measure it on clean code and learn 3,000 is the noise floor |
| A pattern matches the word "should" | Ships, nobody notices | CI fails the false-positive budget |
| Someone asks "what is your precision?" | No answer is possible: you never scanned code without vulnerabilities | 0.008 findings per 100 LOC on 285k lines of clean code |
| A rule fires on a security control | Reported as a vulnerability | Regression test keeps it silent |
| CVSS score for the same finding | Differs between runs, a model wrote it | Computed from the FIRST spec, identical every run |

**Result of fixing that:** on 285,463 lines of clean, officially maintained MCP code, findings went from **3,642 to 23**, a 160x reduction, with **one** above the reporting confidence threshold, and that one is a genuine bug in the SDK.


---

## Try it in thirty seconds

The repository ships the **same MCP server twice**: `demo/vulnerable/` and `demo/safe/`.
Same files, same functions, same names. Every vulnerability in the first is fixed in the
second.

```bash
git clone https://github.com/DINAKAR-S/Agentic-MCP-Scanner
cd Agentic-MCP-Scanner
pip install -e mcp-scan

mcpvuln demo/vulnerable      # 20 findings, 12 categories, all four layers
mcpvuln demo/safe            # 0 findings
```

No API key. No network. Under a second.

The second command is the one that matters. Any scanner finds planted bugs; a scanner
that also fires on the fixed version is not measuring anything. See
[demo/README.md](demo/README.md) for what is planted and how each issue was fixed.

---

## Install

```bash
pip install mcpvuln
```

> **Not on PyPI yet.** Until it is, use the release wheel or a source checkout below.
> _(Delete this note once `twine upload` has run.)_

Core install pulls a single dependency and needs no credentials. Everything else is an
extra:

```bash
pip install "mcpvuln[github]"      # scan a GitHub URL directly
pip install "mcpvuln[narrative]"   # model-written analyst commentary
pip install "mcpvuln[intel]"       # external advisory lookup
pip install "mcpvuln[all]"         # all of the above
```

<details>
<summary>Other ways to install</summary>

**From a GitHub release**, without PyPI:

```bash
pip install https://github.com/DINAKAR-S/Agentic-MCP-Scanner/releases/download/v0.2.0/mcpvuln-0.2.0-py3-none-any.whl
```

**From source**, which is what you want if you intend to run the benchmark or the demo:

```bash
git clone https://github.com/DINAKAR-S/Agentic-MCP-Scanner
cd Agentic-MCP-Scanner
pip install -e "mcp-scan[all]"
```

**Verify the install:**

```bash
mcpvuln --version
mcpvuln --self-check      # validates the rule set: 29 rules, no duplicate ids
```

</details>

## Use

```bash
mcpvuln ./my-mcp-server                              # offline. no API key needed.
mcpvuln https://github.com/org/repo                  # ingest from GitHub
mcpvuln ./repo --json scan.json                      # emit the scan contract
mcpvuln ./repo --min-confidence 0.7                  # tighten the threshold
mcpvuln ./repo --fail-on high                        # exit non-zero, for CI
mcpvuln ./repo --narrative                           # add model commentary
mcpvuln --self-check                                 # validate the pattern set
```

**Detection needs no credentials.** No `GOOGLE_API_KEY`, no `OPENAI_API_KEY`, no network. Only `--narrative` and `--threat-intel` call out, and both degrade to a warning if their key is missing.

## What it detects

Twenty-seven rules across four layers, each carrying a confidence prior and CVSS v4.0 base metrics.

| Layer | Covers |
|---|---|
| **MCP** | JWT verification disabled, weak HS256 secrets, agent-card auto-verification, audit-log mutation, privileged containers and `docker.sock` mounts, pipe-to-shell installs, tool-poisoning sinks, plaintext transport to non-loopback hosts |
| **Agentic AI** | Trust scores computed but never enforced as an authorisation floor, unscoped cross-agent memory queries, shell and REPL tools handed to an agent, unsigned goal mutation |
| **LLM** | Untrusted input concatenated into a system prompt, model context populated from a fetched or decoded remote source |
| **Traditional web** | Command injection, SQL injection, XSS, path traversal, hardcoded secrets, weak crypto, insecure RNG, unsafe deserialisation, dynamic execution |

Run `mcpvuln --self-check` to list them and validate the set.

## How it works

```
ingest  ->  detect  ->  score  ->  report
```

- **detect** is deterministic regex over whole files, with comment, docstring and prose suppression, per-pattern case sensitivity, and a confidence score derived from the pattern's prior and the path it was found in. No model.
- **score** computes CVSS v4.0 base scores through the [`cvss`](https://pypi.org/project/cvss/) implementation of the FIRST specification, and evaluates the SSVC deployer decision tree. Both are reproducible. `Exploitation` is never reported as `active`, because a source scanner observes code, not exploitation in the wild.
- **report** renders Markdown with no model call. `--narrative` optionally adds written analysis on top, receiving the structured scan contract and processing **every** reportable finding in batches.

The boundary between stages is a versioned JSON document, the **scan contract**. Save it with `--json`, diff it across commits, score it offline, feed it to something else.

## The benchmark

```bash
python benchmark/run_benchmark.py --fetch
python benchmark/run_benchmark.py
```

Clones two official MCP reference implementations at pinned commits, scans them, and reports findings per 100 LOC. They contain no known vulnerabilities of the classes under test, so **every finding is a candidate false positive**. CI fails if the rate exceeds 0.05 per 100 LOC.

| Corpus | Commit | Lines |
|---|---|---|
| `modelcontextprotocol/python-sdk` | `d060b36` | 260,948 |
| `modelcontextprotocol/servers` | `d73f99e` | 24,515 |

| Version | Findings | Per 100 LOC |
|---|---|---|
| v0.1.0 | 3,642 | 1.28 |
| v0.2.0 | 23 | 0.008 |

## What is not built yet

Being explicit, because the gap between what a security tool claims and what it does is itself a security problem.

| Not built | What that means for you today |
|---|---|
| **Recall is not measured against a public vulnerable corpus** | The false-positive rate above is solid. The false-*negative* rate is not published, because the vulnerable corpus it was measured against is not yet released. Do not read a clean report as an absence of vulnerabilities. |
| **No runtime or protocol-state analysis** | Detection is static and line-oriented. Vulnerabilities defined by protocol state, whether a nonce is checked before accept, whether a trust score gates an action, are localisable but not reliably classifiable. This is the main known ceiling. |
| **No taint tracking** | A pattern sees one construct, not whether attacker-controlled data actually reaches it. Expect false positives on defensive code that mentions the same constructs. |
| **Category assignment is weaker than localisation** | The tool is better at finding the vulnerable file than at naming the vulnerability. Adjacent categories, the three identity-forgery variants especially, get confused. |
| **`--narrative` output is not reproducible** | It is a language model. The deterministic report underneath it is reproducible; the commentary is not. Do not cite narrative text as a measurement. |
| **Python is the only language with real context analysis** | Comment and string suppression uses `tokenize` for Python and a line-prefix heuristic elsewhere. JavaScript, Go and Rust get weaker suppression and therefore more noise. |
| **No autofix** | Findings carry remediation text. Nothing is changed for you. |

## Development

```bash
pip install -r mcp-scan/requirements-dev.txt
pytest mcp-scan/tests/ -q
ruff check mcp-scan/mcpvuln
```

The test suite encodes the defects that shipped in v0.1.0 as regression tests: the word "should" must not be a supply-chain attack, `includes(` must not be weak cryptography, `allowed_origins=["http://127.0.0.1"]` must not be rogue server impersonation, and no finding may be silently truncated out of a report.

## Contributing

Rules and patterns are the part most worth contributing to, and the bar is specific:
**a new rule must come with a true-positive test, a false-positive test, and a run of
the benign benchmark showing it costs nothing.** See [CONTRIBUTING.md](CONTRIBUTING.md).

Found a vulnerability class the scanner misses? Open an issue with a minimal code
sample. That is the most useful thing anyone can send.

## Security

To report a vulnerability **in this tool**, see [SECURITY.md](SECURITY.md). Please do not
open a public issue for it.

## Citing this work

This tool accompanies a paper under review. See [CITATION.cff](CITATION.cff), or use
GitHub's "Cite this repository" button.

## Changelog

See [CHANGELOG.md](CHANGELOG.md). The short version: v0.2.0 reduced false positives on
clean code by 160x and made scoring reproducible.

## License

MIT. See [LICENSE](LICENSE).
