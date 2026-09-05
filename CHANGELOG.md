# Changelog

Notable changes to mcpvuln. Versions follow [semantic versioning](https://semver.org/).

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

[0.2.0]: https://github.com/DINAKAR-S/Agentic-MCP-Scanner/releases/tag/v0.2.0
[0.1.0]: https://github.com/DINAKAR-S/Agentic-MCP-Scanner/releases/tag/v0.1.0
