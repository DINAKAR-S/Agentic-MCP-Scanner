## What this changes

<!-- One or two sentences. -->

## If this adds or changes a detection rule

- [ ] True-positive test added: vulnerable code the rule must flag
- [ ] **False-positive test added**: correct code mentioning the same constructs that must stay silent
- [ ] Benign benchmark run, and the rate did not increase

```
paste the output of: python benchmark/run_benchmark.py
```

## Checks

- [ ] `pytest tests/ -q` passes
- [ ] `ruff check mcpvuln benchmark tests` passes
- [ ] `mcpvuln --self-check` passes
- [ ] `mcpvuln ../demo/vulnerable` and `../demo/safe` still give 20 and 0

<!-- Detection must stay deterministic and must never require an API key. -->
