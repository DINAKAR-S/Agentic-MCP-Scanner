# Changelog

Notable changes to mcpvuln. Versions follow [semantic versioning](https://semver.org/).

## [0.3.0] - 2026-09-05

The headline: fourteen new rules for the MCP vulnerability classes disclosed as CVEs
during 2025 and 2026, calibrated on **55 third-party MCP servers (840,905 lines)** chosen
for being obscure rather than popular, and a second public fixture corpus that scores
them. The paper's 22-instance corpus is untouched and still scores exactly as published:
precision 1.000, recall 0.864, F1 0.927.

### Detection

- **SSRF from a tool's URL argument** (`web.ssrf.tool_argument_url`), the shape of
  CVE-2025-65513, CVE-2026-26118, CVE-2026-27826 and TRA-2025-36. The rule runs only in
  files that define MCP tools and show no private-address or allow-list check.
- **Argument injection** into `git`, `kubectl`, `docker`, `ssh` and similar
  (`web.argument_injection.cli_list`), the shape of CVE-2025-68144 in Anthropic's
  mcp-server-git. An argument list that passes `"--"` before the caller's values is exempt.
- **Prefix-only path containment** (`web.path_traversal.startswith_containment`),
  CVE-2025-66689 and CVE-2025-53109/53110: `.startswith(root)` in a file that never
  canonicalises a path.
- **DNS-rebinding protection explicitly disabled**
  (`mcp.dns_rebinding.protection_disabled`), CVE-2025-66414 and CVE-2025-66416. Three of
  the 55 real servers do this. An informational sibling flags an HTTP transport with no
  transport-security settings in the file at all.
- **All-interface bind with no authentication in sight**
  (`mcp.network_exposure.bind_all_interfaces`), CVE-2026-23744 and CVE-2025-49596.
- **One HTTP transport shared by every client** (`mcp.session.shared_http_transport`),
  CVE-2026-25536.
- **JavaScript command injection** through `execSync` on a template literal or a
  concatenation (`web.cmd_injection.js_exec_interpolated`; CVE-2025-53355, CVE-2025-53967,
  CVE-2026-0755) and `spawn` with `shell: true` (`web.cmd_injection.spawn_shell_true`).
- **A shell started through an argument list**, `["bash", "-lc", command]`
  (`agent.excessive_agency.shell_argv`).
- **Line jumping**, **cross-server tool shadowing** and **invisible Unicode** in tool
  metadata (`mcp.line_jumping.*`, `mcp.tool_shadowing.*`, `mcp.hidden_unicode.*`), after
  Trail of Bits and Invariant Labs.
- `subprocess ... shell=True` is now found behind nested parentheses, which a real server
  used (`subprocess.run(subprocess.list2cmdline(cmd), ..., shell=True)`), and
  `asyncio.create_subprocess_shell` is treated as the same sink. Both were misses on a
  third-party deliberately vulnerable file.
- A **rug-pull rule was written and removed**. It matched `await client.listTools()`,
  which is how every correct client lists tools: 26 hits on the official SDK, all false.
  A rule that fires on all correct code is not a detection. `docs/cve-coverage.md` lists
  it and the other classes that deliberately have no rule.

### Precision, measured on code nobody wrote for this tool

The first run of the previous rule set on the 55 servers reported 103 findings; adjudicated
by hand, 6 were plausible defects. Three idioms accounted for most of the rest, and each
is now excluded explicitly rather than by lowering a threshold:

- `f"... IN ({','.join('?' * n)})"` and `f"... FROM {TABLE_CONSTANT}"` are not SQL
  injection; nor is `'%'` inside a quoted string (`strftime('%s')`) the formatting
  operator. Identifier interpolation into `SET`, `SAVEPOINT`, `INSTALL` and other
  statements that cannot take a bound parameter is now a separate informational rule.
- MD5 or SHA-1 as a content fingerprint or cache key is informational; the reportable rule
  needs a password, credential or signature in the same expression.
- A UTF-8 byte-order mark at the start of a `.cs` file is not a hidden instruction. The
  analyzer strips a leading BOM before matching, and the invisible-Unicode rule is anchored
  to the line so code that *strips* those characters is not reported for naming them.
- A method *definition* called `exec` (`protected exec(sql: string)`) is not dynamic
  execution.

After the changes the same 55 servers (1,162,650 lines once the largest finished) report
**30 findings**, of which **22** were judged plausible defects on manual review: three
servers with DNS-rebinding protection switched off, two bound to every interface with no
authentication, a committed 64-hex API key in a `docker-compose.yml`, a shell-as-a-tool
server, a `subprocess.run(list2cmdline(cmd), shell=True)`, and a short-link resolver that
follows redirects from any host that merely *contains* the expected domain. Plausible
means "worth a human's time", not "confirmed exploitable"; the eight remaining are HTTP
wrappers over a fixed base URL and a WeChat-mandated SHA-1.

On the 285,463-line benign corpus the raw count went from 21 to **38** (0.013 per 100
lines, under the 0.05 CI budget) and the reportable count from 1 to **3**. All three are
recorded in `benchmark/corpus.json`: the official fetch server retrieving whatever URL the
model supplies, `shell=True` on an argument list in the SDK's CLI, and the SDK's own
backward-compatibility fallback that constructs `TransportSecuritySettings` with protection
off. Two further hits went away for the right reason: the fixed git server rejects
option-shaped targets three lines above the call the rule matches, so the rule now stands
down in any file that checks for a leading `-`.

### Analyzer

- Rules can carry two **file-level gates**: `requires`, a regex that must match somewhere
  in the file, and `absent`, one that must match nowhere. A single-site regex cannot say
  "this file defines MCP tools" or "this file never calls realpath"; a gate can.
  `--self-check` validates them.
- A leading UTF-8 byte-order mark is stripped before matching.
- **A hang found by the pre-release stress pass, present since 0.1.0.** The
  cross-tenant cache rule began with an unbounded `\w*` in front of a literal, which is
  quadratic; a 2 MB single-line file made one scan run for over ten minutes. The prefix
  is now bounded, and a test feeds every rule six hostile files (a 400 KB line, 2,000
  nested parentheses, 10,000 alternating quotes, a 10,000-placeholder f-string, 10,000
  repeated `<IMPORTANT>` tags, 50,000 zero-width characters) with a two-second ceiling
  each.

### Benchmark

- A second fixture corpus, `demo/vulnerable-2026` and `demo/safe-2026`, with
  `demo/ground-truth-2026.json` naming the CVE each of its 16 instances mirrors.
  `python benchmark/score_demo.py --corpus 2026` scores it (16 TP, 0 FP, 0 FN) and
  `--corpus paper` scores the frozen 22-instance set. CI runs both and requires the fixed
  halves to be silent.

### Packaging

- `Dockerfile` and a release workflow that publishes `ghcr.io/dinakar-s/mcpvuln` to
  GitHub Packages on every `v*` tag and attaches the sdist and wheel to the release.
- `CITATION.cff`: the author's name is Dinakar, family name S.
- 216 tests, up from 154.

## [0.2.1] - 2026-09-05

Packaging only. No change to detection, scoring or reporting.

- **Fixed the PyPI page showing only a one-line summary instead of the README.**
  `python -m build` builds the wheel from the sdist, and the README lived only at the
  repository root, so it was absent at wheel-build time and `setup.py` silently fell
  back to the short description. A PyPI-facing README now ships inside the package
  directory, written with absolute links because relative ones do not resolve on PyPI.
  `setup.py` also rejects a stub shorter than 500 characters rather than degrading
  quietly.
- Expanded project URLs from two to eight: homepage, source, issues, changelog,
  benchmark, contributing, security policy and release notes.
- Added classifiers for Python 3.13, console environment, testing topic and typing.

## [0.2.0] - 2026-09-04

The headline: on 285,463 lines of clean, officially maintained MCP code, findings went
from **3,642 to 23**, a 160-fold reduction, and scoring became reproducible.

### Detection

- **Fixed a regular expression that produced 2,061 of 3,642 findings.** `wget .* | sh`
  used an unescaped `|`, which in a regular expression is alternation rather than a shell
  pipe, so the alternative `' sh'` matched the word **"should"**.
- **Fixed four duplicate dictionary keys** that silently discarded four pattern lists.
  33 keys were written, 29 survived, and 11 regular expressions never executed.
- **Removed twenty unanchored bare-substring patterns** (`latest`, `http://`, `open(`,
  `while True`) that fired on comments, documentation and URLs.
- **Made case-insensitivity opt-in per pattern.** Applied globally, `DES\s*\(` matched
  `includes(`.
- **Matching is now whole-file rather than line-by-line**, so patterns can span lines.
- **Comments, docstrings and prose are suppressed.** Triple-quoted strings are treated as
  documentation, so a credential in a usage example is no longer reported.
- **Findings carry a confidence score** derived from the pattern's prior and the path
  class, used for ranking, filtering and the informational threshold.
- **Added suppression directives**: `# mcpvuln: ignore-file`, `# mcpvuln: ignore`, and
  `# mcpvuln: ignore[rule.id]`.
- Added cross-tenant context bleed detection, and fixed two rules that were silently
  failing: agent-card verification (the flag is a dict key, and a dict key is a string
  literal) and weak JWT secrets (the algorithm had to precede the secret).

### Scoring

- **CVSS v4.0 base scores are computed**, through the [`cvss`](https://pypi.org/project/cvss/)
  implementation of the FIRST specification, rather than written in prose by a language
  model. The same finding now scores identically on every run.
- **SSVC is evaluated as the published decision tree.** `Exploitation` is never reported
  as `active`, because a source scanner observes code, not exploitation in the wild.
- Risk index is a documented function of severity, confidence and urgency.
- Malformed metric values are sanitised instead of aborting the scan.

### Architecture

- **New scan contract**: a versioned JSON document that is the only thing crossing a
  stage boundary. Save it with `--json`, diff it across commits, score it offline.
- `SecurityAnalysisTeam` is now `SecurityAnalysisPipeline`. The previous class presented
  the stages as a coordinating multi-agent team, but the coordinating model was
  constructed and never invoked, and `OPENAI_API_KEY` appeared nowhere in the repository.
  The old name remains as a deprecated alias.
- **Detection requires no API key and no network.** Only `--narrative` and
  `--threat-intel` reach out, and both degrade to a warning without their key.
- **Removed `findings[:20]`**, which silently discarded 99.4% of findings on a repository
  of any size. All reportable findings are now processed, in batches.
- Reports gained a leadership risk summary and a plain-language explanation per finding,
  both generated deterministically.
- A failed threat-intelligence crawl is no longer appended to the results as though it
  were a vulnerability, and a failed narrative batch no longer discards a completed scan.

### Interface

- New flags: `--out`, `--json`, `--min-confidence`, `--fail-on`, `--self-check`,
  `--model`, `--quiet`.
- Reports no longer embed the author's absolute filesystem path.
- Threat-intelligence sources moved out of `cli.py` into configuration, overridable with
  `MCPVULN_INTEL_SOURCES`.

### Testing and infrastructure

- **140 tests**, from zero. Every defect above is held down by a regression test, and
  `tests/test_paper_algorithms.py` asserts the implementation matches the published
  algorithms step by step.
- **CI** on Linux and Windows across Python 3.9, 3.11 and 3.12, plus lint and a benign
  benchmark job that **fails if the false-positive rate exceeds 0.05 per 100 LOC**.
- **New benchmark** with a pinned benign corpus, so precision is measurable rather than
  assumed.
- **New demo**: `demo/vulnerable` and `demo/safe`, the same MCP server twice with every
  issue fixed in the second. 20 findings against 0.
- Dependencies pinned. Core install is a single package; everything else is an extra.
- Fixed an install that had been broken since the first release: `setup.py` read
  `README.md` from the working directory rather than relative to itself, so the
  documented `pip install -e "mcp-scan[all]"` failed on a fresh clone.

## [0.1.0] - 2025-07-20

Initial release. Regular-expression detection with language-model reporting.

Tagged so the version evaluated in the accompanying paper stays reproducible. **Not
recommended for use**: measured at 1.28 findings per 100 lines of clean code, of which an
adjudicated sample of twenty-five contained no true positives.

[0.3.0]: https://github.com/DINAKAR-S/Agentic-MCP-Scanner/releases/tag/v0.3.0
[0.2.1]: https://github.com/DINAKAR-S/Agentic-MCP-Scanner/releases/tag/v0.2.1
[0.2.0]: https://github.com/DINAKAR-S/Agentic-MCP-Scanner/releases/tag/v0.2.0
[0.1.0]: https://github.com/DINAKAR-S/Agentic-MCP-Scanner/releases/tag/v0.1.0
