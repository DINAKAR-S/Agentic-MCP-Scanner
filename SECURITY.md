# Security policy

## Reporting a vulnerability in this tool

Please report privately, not as a public issue.

Use [GitHub's private vulnerability reporting](https://github.com/DINAKAR-S/Agentic-MCP-Scanner/security/advisories/new)
on this repository, or email **dinakars2003@gmail.com** with `mcpvuln security` in the
subject.

Please include what you did, what happened, and what you expected. A minimal reproduction
is worth more than a long description. Expect an acknowledgement within a few days; this
is a research project, not a staffed product, and the response time reflects that.

## Scope

**In scope:**

- code execution, path traversal or file disclosure triggered by scanning a hostile
  repository
- a crafted source file that hangs the scanner (catastrophic regular-expression
  backtracking)
- credential leakage into a report, a log, or the scan contract
- anything that makes the scanner report a clean result on code it should flag, if it can
  be triggered deliberately

**Out of scope:**

- ordinary false positives and false negatives. Those are
  [normal issues](https://github.com/DINAKAR-S/Agentic-MCP-Scanner/issues) and
  [CONTRIBUTING.md](CONTRIBUTING.md) explains how to report them well.
- vulnerabilities in `demo/vulnerable/`. That directory is **deliberately insecure** and
  exists to be scanned. Do not deploy it.
- vulnerabilities in the benchmark corpus. Those belong to their upstream projects.

## What this tool assumes about its input

Worth stating plainly, because it is a scanner and people point it at hostile code.

**Scanned code is never executed.** Detection reads files as text and applies regular
expressions. It does not import, evaluate, or run anything from the target, and it does
not follow symlinks out of the scanned tree.

**Detection makes no network calls and needs no credentials.** Only two opt-in features
reach the network: `--narrative` sends finding metadata (file paths, line numbers, rule
ids, code snippets) to a language model, and `--threat-intel` fetches public advisories.
Both are off by default. **If you are scanning something confidential, do not pass
`--narrative`**, because snippets of that code leave your machine.

**Reports contain code snippets from the scanned repository.** Treat a report with the
same care as the source it came from before sharing it.

## Known limitations that are not vulnerabilities

These are documented in the [README](README.md#what-is-not-built-yet) and are design
limits rather than defects:

- recall on unseen code is unmeasured, so a clean report is not evidence of safety
- detection is static, so vulnerabilities that only manifest at runtime can be located
  but not reliably classified
- there is no taint tracking, so a rule sees a construct and not whether attacker
  controlled data actually reaches it
- `--narrative` output is model-generated and not reproducible

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | yes |
| 0.1.x | no, superseded. It is tagged only so the version evaluated in the accompanying paper stays reproducible, and it has a false-positive rate roughly 160 times higher. |
