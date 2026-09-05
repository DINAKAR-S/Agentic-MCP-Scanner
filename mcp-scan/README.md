# mcpvuln

[![PyPI](https://img.shields.io/pypi/v/mcpvuln)](https://pypi.org/project/mcpvuln/)
[![Downloads](https://img.shields.io/pypi/dm/mcpvuln)](https://pypi.org/project/mcpvuln/)
[![CI](https://github.com/DINAKAR-S/Agentic-MCP-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/DINAKAR-S/Agentic-MCP-Scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-yellow)](https://github.com/DINAKAR-S/Agentic-MCP-Scanner/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)

**A vulnerability scanner for Model Context Protocol codebases that proves how often it is wrong.**

MCP lets an agent discover and call tools at runtime, from servers somebody else operates. That moves the unit of trust from a single function call to a whole protocol session, and the failures that follow have no equivalent in ordinary application security: forged agent identities, trust scores computed but never enforced, audit logs that can be rewritten, one tenant's context served to another.

There are scanners already. What none of them ships is a way to tell how much of the output is real, because they are only ever evaluated against code known to be broken. This one ships a **benign control corpus** as well, so precision is measured rather than assumed.

```bash
pip install mcpvuln
```

## Try it in thirty seconds

```bash
git clone https://github.com/DINAKAR-S/Agentic-MCP-Scanner
mcpvuln Agentic-MCP-Scanner/demo/vulnerable   # 20 findings, 12 categories, all four layers
mcpvuln Agentic-MCP-Scanner/demo/safe         # 0 findings
```

The repository ships the **same MCP server twice**, with every vulnerability in the first one fixed in the second. The second command is the one that matters: any scanner finds planted bugs, but one that also fires on the corrected version is not measuring anything.

No API key. No network. Under a second.

## Measured, not claimed

**Precision, recall and F1** against a public ground truth of 22 documented vulnerabilities ([`benchmark/score_demo.py`](https://github.com/DINAKAR-S/Agentic-MCP-Scanner/blob/main/mcp-scan/benchmark/score_demo.py)):

| | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| **All layers** | 19 | 0 | 3 | **1.000** | **0.864** | **0.927** |
| LLM | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Traditional web | 5 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| MCP | 11 | 0 | 1 | 1.000 | 0.917 | 0.957 |
| Agentic AI | 2 | 0 | 2 | 1.000 | 0.500 | 0.667 |

**False positives** on 285,463 lines of clean, officially maintained MCP code, where every finding is a candidate false positive ([`benchmark/`](https://github.com/DINAKAR-S/Agentic-MCP-Scanner/tree/main/mcp-scan/benchmark)):

| Version | Findings | Per 100 LOC |
|---|---|---|
| 0.1.0 | 3,642 | 1.28 |
| **0.2.0** | **23** | **0.008** |

A 160-fold reduction. CI fails the build if that rate rises above 0.05.

## Usage

```bash
mcpvuln ./my-mcp-server                    # offline, no API key needed
mcpvuln https://github.com/org/repo        # ingest from GitHub
mcpvuln ./repo --json scan.json            # emit the scan contract
mcpvuln ./repo --min-confidence 0.7        # tighten the threshold
mcpvuln ./repo --fail-on high              # exit non-zero, for CI
mcpvuln --self-check                       # validate the rule set
```

**Detection needs no credentials.** No `GOOGLE_API_KEY`, no `OPENAI_API_KEY`, no network. Only the optional `--narrative` and `--threat-intel` reach out, and both degrade to a warning without their key.

### Extras

```bash
pip install "mcpvuln[github]"      # scan a GitHub URL directly
pip install "mcpvuln[narrative]"   # model-written analyst commentary
pip install "mcpvuln[intel]"       # external advisory lookup
pip install "mcpvuln[all]"         # all of the above
```

## What it detects

29 rules across four layers, each carrying a confidence prior and CVSS v4.0 base metrics.

| Layer | Covers |
|---|---|
| **MCP** | JWT verification disabled, weak HS256 secrets, agent-card auto-verification, audit-log mutation, privileged containers and `docker.sock` mounts, pipe-to-shell installs, tool-poisoning sinks, cross-tenant context bleed, plaintext transport |
| **Agentic AI** | Trust scores computed but never enforced as an authorisation floor, unscoped cross-agent memory queries, shell and REPL tools handed to an agent, unsigned goal mutation |
| **LLM** | Untrusted input concatenated into a system prompt, model context populated from a fetched or decoded remote source |
| **Traditional web** | Command injection, SQL injection, XSS, path traversal, hardcoded secrets, weak crypto, insecure RNG, unsafe deserialisation, dynamic execution |

## How it works

```
ingest  ->  detect  ->  score  ->  report
```

- **detect** is deterministic pattern matching over whole files, with comment, docstring and prose suppression, per-pattern case sensitivity, and a confidence score. No model.
- **score** computes CVSS v4.0 base scores through the [`cvss`](https://pypi.org/project/cvss/) implementation of the FIRST specification, and evaluates the SSVC deployer decision tree. Both are reproducible; the same finding scores identically on every run.
- **report** renders Markdown with no model call, including a plain-language summary per finding.

The boundary between stages is a versioned JSON **scan contract**. Save it with `--json`, diff it across commits, score it offline.

## What is not built yet

Stated plainly, because the gap between what a security tool claims and what it does is itself a security problem.

- **Recall on unseen code is unmeasured.** A clean report is not evidence of safety.
- **No runtime or protocol-state analysis.** Vulnerabilities defined by protocol state can be localised but not reliably classified. This is the main known ceiling, and it is why the Agentic AI layer scores lowest above.
- **No taint tracking.** A rule sees a construct, not whether attacker-controlled data reaches it.
- **`--narrative` output is not reproducible.** It is a language model; the deterministic report underneath it is.
- **Python has the strongest context analysis.** Other languages get a weaker heuristic and therefore more noise.

Full detail in the [limitations table](https://github.com/DINAKAR-S/Agentic-MCP-Scanner#what-is-not-built-yet).

## Links

- **Source and issues:** <https://github.com/DINAKAR-S/Agentic-MCP-Scanner>
- **Changelog:** <https://github.com/DINAKAR-S/Agentic-MCP-Scanner/blob/main/CHANGELOG.md>
- **Contributing:** <https://github.com/DINAKAR-S/Agentic-MCP-Scanner/blob/main/CONTRIBUTING.md> — a new rule needs a true-positive test, a false-positive test, and a benchmark run showing it costs nothing
- **Security policy:** <https://github.com/DINAKAR-S/Agentic-MCP-Scanner/blob/main/SECURITY.md>

## License

MIT
