# mcpvuln

Vulnerability detection for Model Context Protocol codebases, with a benign control corpus so you can tell how much of the output is noise.

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
| Someone asks "what is your precision?" | No answer is possible: you never scanned code without vulnerabilities | 0.009 findings per 100 LOC on 285k lines of clean code |
| A rule fires on a security control | Reported as a vulnerability | Regression test keeps it silent |
| CVSS score for the same finding | Differs between runs, a model wrote it | Computed from the FIRST spec, identical every run |

**Result of fixing that:** on 285,463 lines of clean, officially maintained MCP code, findings went from **3,642 to 26**, a 142x reduction, with 5 above the reporting confidence threshold.

---

## Install

```bash
pip install -e "mcp-scan[all]"
```

Core install needs one dependency (`cvss`). Everything else is an extra:

```bash
pip install -e mcp-scan                  # detection, scoring, reports. no network.
pip install -e "mcp-scan[github]"        # scan a GitHub URL directly
pip install -e "mcp-scan[narrative]"     # model-written analyst commentary
pip install -e "mcp-scan[intel]"         # external advisory lookup
```

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

Twenty-six rules across four layers, each carrying a confidence prior and CVSS v4.0 base metrics.

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
| v0.2.0 | 26 | 0.009 |

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

## License

MIT. See [LICENSE](LICENSE).
