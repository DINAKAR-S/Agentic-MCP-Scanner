# Contributing

The most useful contribution is a **detection rule**, and the second most useful is a
**false positive you found**. Both are welcome, and both have a specific bar.

## The bar for a new rule

A security scanner is only as good as its precision, so a rule is not accepted on the
strength of what it catches. Every new rule needs three things:

1. **A true-positive test.** Vulnerable code the rule must flag.
2. **A false-positive test.** Correct code that mentions the same constructs and must
   stay silent. This is the one people skip, and it is the one that matters.
3. **A benign benchmark run showing the rule costs nothing.**

```bash
cd mcp-scan
pytest tests/ -q
python benchmark/run_benchmark.py --fetch      # first time only
python benchmark/run_benchmark.py
```

The benchmark scans 285,463 lines of officially maintained MCP code that contains no
vulnerabilities of the classes under test, so **every finding it produces is a candidate
false positive**. CI fails if the rate exceeds 0.05 per 100 LOC. It currently sits at
0.008.

If your rule pushes that number up, it is not ready, however real the vulnerability is.
A rule nobody trusts is a rule nobody reads.

## Adding a rule

Rules live in [`mcp-scan/mcpvuln/patterns.py`](mcp-scan/mcpvuln/patterns.py) as data, not
code. Add a `Pattern`:

```python
Pattern(
    id="mcp.your_rule.specific_case",     # unique; duplicates fail a test
    category="your_category",
    layer=LAYER_MCP,                       # LLM | Agentic AI | MCP | Traditional Web
    regex=r"...",
    description="One sentence a reader can act on.",
    confidence=0.75,                       # your honest prior that a hit is real
    cvss=_cvss(av="N", pr="N", vc="H", vi="H"),
    remediation="What to do instead, concretely.",
)
```

Four rules the pattern set enforces, each learned from a defect that shipped:

| Rule | Why |
|---|---|
| No bare substrings | `latest` and `http://` matched documentation and URLs |
| `ignorecase` is opt-in per pattern | global case-insensitivity made `DES\s*\(` match `includes(` |
| Escape shell pipes | `wget .* \| sh` read `\|` as alternation, so `' sh'` matched **"should"**, 1,852 times |
| `allow_in_string` only when the evidence lives in a string | otherwise every credential in a docstring example is reported |

Then add a plain-language impact phrase for your category in
[`mcpvuln/summary.py`](mcp-scan/mcpvuln/summary.py). A test fails without one, because a
finding a non-specialist cannot act on is not finished.

## Reporting a false positive

The single most valuable issue you can file. Include:

- the exact line that was flagged
- the rule id from the report (`mcpvuln --self-check` lists them all)
- why it is correct code

A confirmed false positive becomes a test in
[`tests/test_analyzer.py`](mcp-scan/tests/test_analyzer.py) so it can never come back.

## Reporting a missed vulnerability

Also very welcome. A minimal code sample is enough. If it belongs to a class the tool
does not model at all, say so and it becomes a roadmap item rather than a rule.

## Development

```bash
cd mcp-scan
pip install -e ".[dev]"
pytest tests/ -q
ruff check mcpvuln benchmark tests
mcpvuln --self-check
mcpvuln ../demo/vulnerable      # 20 findings expected
mcpvuln ../demo/safe            # 0 findings expected
```

CI runs on Linux and Windows across Python 3.9, 3.11 and 3.12, plus the lint job and the
false-positive budget gate. All of it must be green.

## Things that will be declined

- A rule without a false-positive test.
- A rule that raises the benign benchmark rate.
- A change that makes detection non-deterministic. The detection layer must produce
  identical output for identical input; a test enforces this.
- Anything that makes an API key necessary for detection. Scanning must work offline.
- Model-generated CVSS or SSVC values. Both are computed, and are meant to stay that way.

## Scope

This project detects vulnerabilities and measures how often it is wrong. It does not fix
code, and there is no plan for it to. See the
[limitations table](README.md#what-is-not-built-yet) for what is deliberately absent.
