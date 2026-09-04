# Security report: mcpvuln

Generated 2026-09-04T13:19:45+00:00 by mcpvuln 0.2.0 (contract schema 1.0).

## Summary

| | |
|---|---|
| Files scanned | 12 |
| Lines scanned | 1,603 |
| Reportable findings | 1 |
| Informational (below confidence threshold) | 0 |

### By severity

| Severity | Findings |
|---|---|
| Critical | 1 |

### By taxonomy layer

| Layer | Findings |
|---|---|
| MCP | 1 |

## Findings

### 1. container_escape in `patterns.py` line 226

- **Layer:** MCP
- **CVSS v4.0:** 9.4 (Critical)
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`
- **SSVC priority:** Out-of-Band
- **Decision path:** Exploitation=poc; Automatable=no; TechnicalImpact=total; MissionImpact=high
- **Risk index:** 78/100
- **Detector confidence:** 0.85  (rule `mcp.docker.privileged`)

Privileged container or Docker socket mount.

```
regex=r"privileged[\"']?\s*[:=]\s*(?:True|true)|--privileged\b|/var/run/docker\.sock",
```

**Remediation.** Never grant privileged mode or mount docker.sock into agent-deployed services.


---

**How to read this.** CVSS v4.0 vectors and base scores are computed from
the finding's metrics using the FIRST specification, and SSVC priorities are
evaluated as a decision tree. Both are reproducible: the same contract always
produces the same scores. Detector confidence is the scanner's own estimate
that a finding is real, and is not part of any standard. `Exploitation` is
never reported as `active`, because static analysis observes code rather than
exploitation in the wild.
