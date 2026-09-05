---
name: False positive
about: The scanner flagged code that is correct
title: "[FP] "
labels: false-positive
---

**The flagged line**

```
paste the exact line here
```

**Rule id** (from the report, or `mcpvuln --self-check`)

`e.g. mcp.no_tls.transport`

**Why this code is correct**

<!-- One or two sentences. This is the part that matters. -->

**Version**

<!-- output of `mcpvuln --version` -->

---

Confirmed false positives become regression tests, so they cannot come back. This is the
most useful kind of issue you can file.
