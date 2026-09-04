# Demo: two MCP servers, one broken and one fixed

> ⚠️ **`demo/vulnerable/` is deliberately insecure. Do not copy any of it into a real
> system, and do not run `install.sh` or `deploy.yml`.** It exists to be scanned.

`demo/vulnerable/` and `demo/safe/` are the **same MCP server, twice**: same files,
same functions, same names. The only difference is that every vulnerability in the
first one has been fixed in the second.

That pairing is the point. A scanner that flags the broken one proves nothing on its
own, because a scanner that flags everything also flags the broken one. What tells you
whether it works is that it goes quiet on the fixed one.

## Try it

```bash
mcpvuln demo/vulnerable
mcpvuln demo/safe
```

Expected:

| Target | Reportable findings |
|---|---|
| `demo/vulnerable` | **20**, across 12 categories and all four taxonomy layers |
| `demo/safe` | **0** |

No API key. No network. Takes under a second.

## What is planted, and where

| Layer | Vulnerability | File | Fixed in `safe/` by |
|---|---|---|---|
| MCP | JWT decoded with signature verification disabled | `identity.py` | verifying on every decode, asymmetric key |
| MCP | Agent card marked verified with no issuer check | `identity.py` | requiring an issuer signature first |
| MCP | Audit log rows deleted and rewritten | `audit.py` | append-only, hash-chained rows |
| MCP | Privileged container mounting the Docker socket | `deploy.yml` | dropped capabilities, no host mount, pinned digest |
| MCP | Remote script piped straight into a shell | `install.sh` | download, verify checksum, then run |
| MCP | Session cache keyed without a tenant | `server.py` | composite `(tenant_id, request_id)` key |
| MCP | Plaintext HTTP to a non-loopback host | `server.py` | TLS |
| Agentic AI | Agent given shell, REPL and file-write tools | `agent.py` | read-only sandboxed tools |
| Agentic AI | Memory search with no agent scoping | `agent.py` | `filter={"agent_id": ...}` |
| Agentic AI | Delegation trust decays but is never enforced | `identity.py` | a minimum-trust authorisation floor |
| Agentic AI | Goal overwritten with no integrity check | `agent.py` | signed goal updates, signer verified |
| LLM | Untrusted input concatenated into a system prompt | `server.py` | untrusted text kept in a user-role message |
| Traditional web | SQL built by string formatting | `server.py` | parameter binding |
| Traditional web | User input concatenated into a shell command | `server.py` | argument list, `shell=False` |
| Traditional web | `shell=True` on a caller-supplied value | `server.py` | argument list, `shell=False` |
| Traditional web | Credential committed in source | `server.py` | read from the environment |
| Traditional web | Untrusted bytes unpickled | `server.py` | JSON |

## Why the fixed version is the interesting half

Every scanner finds planted bugs. The number that decides whether a tool is usable is
how much it says about code that is *fine*, because that is what a real repository is
mostly made of.

`demo/safe/` is a miniature version of the benign corpus in
[`mcp-scan/benchmark/`](../mcp-scan/benchmark/), which measures the same thing at scale:
285,463 lines of officially maintained MCP code, on which this scanner reports 23
findings, one of which is real.

## Fair warning about what this demo is not

These are hand-written fixtures with one clean instance of each class, so detection here
is easier than detection in a real codebase. Treat `demo/vulnerable` as a smoke test that
the rules fire and `demo/safe` as a smoke test that they discriminate, not as evidence of
recall on code you have not seen. The honest numbers are in the benchmark, and the
[limitations table](../README.md#what-is-not-built-yet) says what is still unmeasured.
