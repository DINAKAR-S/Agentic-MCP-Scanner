# mcpvuln: ignore-file
#   This module contains the literal strings the rules match on, so scanning it
#   with its own rules reports the rule definitions as vulnerabilities.
"""Detection patterns, as data.

Every pattern carries the metadata the rest of the pipeline needs: which taxonomy
layer it belongs to, how much to trust it, whether it is meaningful outside code,
and the CVSS v4.0 base metrics to score it with.

Design rules, learned from measuring the previous pattern set against 285k lines of
clean official MCP code (see benchmark/):

1. No bare substrings. Every pattern is anchored to a syntactic construct.
2. ``ignorecase`` is opt-in per pattern, never global. ``DES\\s*\\(`` applied
   case-insensitively matches ``includes(``.
3. ``code_only`` patterns are suppressed inside comments, docstrings and prose.
   ``allow_in_string`` re-permits a pattern inside string literals, for the rules
   whose evidence is a shell command, a SQL statement, a path or a URL.
4. ``confidence`` is a real number the pipeline ranks and filters on. A pattern that
   can only ever be a hint scores low and is reported as informational.
5. Shell pipes are escaped. ``|`` inside a regex is alternation.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Taxonomy layers. Section 3 of the paper is organised on this axis, and the
# benchmark reports against it.
LAYER_LLM = "LLM"
LAYER_AGENT = "Agentic AI"
LAYER_MCP = "MCP"
LAYER_WEB = "Traditional Web"

SEVERITY_ORDER = ["None", "Low", "Medium", "High", "Critical"]


@dataclass(frozen=True)
class Pattern:
    """One detection rule."""

    id: str
    category: str
    layer: str
    regex: str
    description: str
    confidence: float           # 0.0 to 1.0, prior probability this is a real finding
    cvss: Dict[str, str]        # CVSS v4.0 base metrics
    ignorecase: bool = False
    code_only: bool = True      # suppress matches inside comments and prose
    allow_in_string: bool = False   # some evidence legitimately lives in a string
    remediation: str = ""

    _compiled: Optional[re.Pattern] = field(default=None, compare=False, repr=False)

    def compiled(self) -> re.Pattern:
        flags = re.IGNORECASE if self.ignorecase else 0
        return re.compile(self.regex, flags)


# CVSS v4.0 base-metric shorthands. AV attack vector, AC complexity, AT requirements,
# PR privileges required, UI user interaction, VC/VI/VA vulnerable-system impact,
# SC/SI/SA subsequent-system impact.
def _cvss(av="N", ac="L", at="N", pr="N", ui="N", vc="N", vi="N", va="N", sc="N", si="N", sa="N"):
    return {"AV": av, "AC": ac, "AT": at, "PR": pr, "UI": ui,
            "VC": vc, "VI": vi, "VA": va, "SC": sc, "SI": si, "SA": sa}


PATTERNS: List[Pattern] = [

    # ------------------------------------------------------------------ Traditional web
    Pattern(
        id="web.cmd_injection.os_system",
        category="command_injection", layer=LAYER_WEB,
        regex=r"\bos\.system\s*\(\s*[^)]*(?:\+|%|\bf[\"']|\.format\s*\()",
        description="User-controlled data concatenated into os.system().",
        confidence=0.85,
        cvss=_cvss(pr="N", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
        remediation="Use subprocess with an argument list and shell=False. Never build a shell string.",
    ),
    Pattern(
        id="web.cmd_injection.subprocess_shell",
        category="command_injection", layer=LAYER_WEB,
        regex=r"\bsubprocess\.(?:run|call|check_output|Popen|check_call)\s*\([^)]*shell\s*=\s*True",
        description="subprocess invoked with shell=True.",
        confidence=0.70,
        cvss=_cvss(vc="H", vi="H", va="H"),
        remediation="Pass an argument list and drop shell=True.",
    ),
    Pattern(
        id="web.sql_injection.format",
        category="sql_injection", layer=LAYER_WEB,
        regex=(
            # Python: execute("..." % x), ("..." + x), f"...", .format(
            r"\b(?:execute|executemany)\s*\(\s*"
            r"(?:f[\"']"
            r"|[\"'][^\"']*[\"']\s*%"
            r"|[\"'][^\"']*[\"']\s*\+"
            r"|[\"'][^\"']*[\"']\s*\.format\s*\()"
            r"|"
            # JavaScript and TypeScript: db.query("SELECT ..." + x)
            r"\.(?:query|execute|raw)\s*\(\s*[\"'][^\"']*"
            r"(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^)]{0,160}?[\"'][\s\"']*\+"
            r"|"
            # template literal interpolating into SQL
            r"\.(?:query|execute|raw)\s*\(\s*`[^`]*"
            r"(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^`]*\$\{"
        ),
        description="SQL built by string formatting or concatenation rather than parameter binding.",
        confidence=0.85,
        cvss=_cvss(vc="H", vi="H", va="L"),
        remediation="Use parameterised queries. Pass values as the driver's second argument.",
    ),
    Pattern(
        id="web.xss.innerhtml",
        category="xss", layer=LAYER_WEB,
        regex=r"\.innerHTML\s*=\s*[^;]*(?:\+|`\$\{)",
        description="Dynamic value assigned to innerHTML.",
        confidence=0.70,
        cvss=_cvss(ui="A", vc="L", vi="L", sc="L", si="L"),
        remediation="Use textContent, or sanitise with a vetted library before assignment.",
    ),
    Pattern(
        id="web.path_traversal.join_user",
        category="path_traversal", layer=LAYER_WEB,
        regex=r"\bopen\s*\(\s*(?:os\.path\.join\s*\([^)]*\+|[^)]*\+\s*\w*(?:path|file|name|user|input))",
        description="File path assembled from unvalidated input.",
        confidence=0.60,
        cvss=_cvss(vc="H", vi="L"),
        remediation="Resolve to an absolute path and assert it stays within an allowed root.",
    ),
    Pattern(
        id="web.hardcoded_secret.assignment",
        category="hardcoded_secrets", layer=LAYER_WEB,
        # Require a value that looks like a real secret, not a placeholder.
        regex=(
            r"(?:password|passwd|api_key|apikey|secret|token|private_key)"
            r"\s*[:=]\s*[\"']"
            # not a placeholder, not a field name, not an environment variable name
            r"(?![\"']|\s|<|\{|\$|your[-_ ]|xxx+|placeholder|example|changeme"
            r"|redacted|test|dummy|fake|sample|foo|bar|opaque[-_]|super[-_]secret"
            # (?-i:) because this rule is case-insensitive overall; without it
            # this clause would match any alphanumeric value and reject every
            # real credential.
            r"|header\.payload|(?-i:[A-Z][A-Z0-9_]{5,})[\"']"
            r"|(?:oauth|idp|client|api|auth|mcp)[-_](?:client[-_])?"
            r"(?:secret|token|key|id)[\"']"
            r"|\*+)"
            r"[A-Za-z0-9_\-+/=.]{16,}[\"']"
        ),
        description="Credential-shaped literal assigned in source.",
        confidence=0.75, ignorecase=True,
        cvss=_cvss(vc="H", vi="H"),
        allow_in_string=True,
        remediation="Load from the environment or a secret manager. Rotate anything committed.",
    ),
    Pattern(
        id="web.weak_crypto.hash",
        category="weak_crypto", layer=LAYER_WEB,
        regex=r"\bhashlib\.(?:md5|sha1)\s*\(|\bMessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']",
        description="Broken hash used where a cryptographic hash is expected.",
        confidence=0.55,
        cvss=_cvss(vi="L"),
        remediation="Use SHA-256 or better. For passwords use argon2 or bcrypt.",
    ),
    Pattern(
        id="web.weak_crypto.cipher",
        category="weak_crypto", layer=LAYER_WEB,
        regex=r"\b(?:DES|RC4|Blowfish)\.new\s*\(|Cipher\.getInstance\s*\(\s*[\"'](?:DES|RC4)",
        description="Broken cipher construction.",
        confidence=0.80,
        cvss=_cvss(vc="H", vi="L"),
        remediation="Use AES-GCM or ChaCha20-Poly1305.",
    ),
    Pattern(
        id="web.insecure_random.security_context",
        category="insecure_random", layer=LAYER_WEB,
        regex=r"\brandom\.(?:random|randint|choice)\s*\([^)]*\)\s*(?:#.*)?$(?=[\s\S]{0,0})|(?:token|secret|nonce|salt|session_id|password)\s*=\s*random\.",
        description="Non-cryptographic RNG used for a security value.",
        confidence=0.70, ignorecase=True,
        cvss=_cvss(ac="H", vc="L", vi="L"),
        remediation="Use the secrets module, or os.urandom.",
    ),
    Pattern(
        id="web.unsafe_deserialization",
        category="unsafe_deserialization", layer=LAYER_WEB,
        regex=r"\b(?:pickle|cPickle|dill)\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.(?:Safe|CSafe))",
        description="Deserialisation of untrusted data.",
        confidence=0.75,
        cvss=_cvss(vc="H", vi="H", va="H"),
        remediation="Use json, or yaml.safe_load. Never unpickle untrusted bytes.",
    ),
    Pattern(
        id="web.dynamic_exec",
        category="dynamic_code_execution", layer=LAYER_WEB,
        regex=(
            # eval/exec reached by non-literal input. Deliberately NOT a bare
            # `exec(`: in JavaScript that is RegExp.prototype.exec, and generated
            # TypeScript .d.ts files declare URLPattern.exec, neither of which
            # executes anything. Require a Python builtin call or an explicit
            # child_process / Function constructor.
            r"(?:^|[^.\w])(?:eval|exec)\s*\(\s*"
            r"(?![\"']\s*\))"
            r"(?=[^)]*(?:\+|input|request|body|payload|param|arg|user|f[\"']))"
            r"|"
            r"\bchild_process\.(?:exec|execSync)\s*\("
            r"|"
            r"\bnew\s+Function\s*\("
        ),
        description="eval/exec reached by non-literal input.",
        confidence=0.80,
        cvss=_cvss(vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
        remediation="Remove dynamic execution. If unavoidable, restrict to a parsed AST allow-list.",
    ),

    # ------------------------------------------------------------------ MCP layer
    Pattern(
        id="mcp.no_tls.transport",
        category="insecure_transport", layer=LAYER_MCP,
        # Only flag a non-loopback plaintext endpoint. localhost is normal in dev.
        regex=r"[\"']http://(?!localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|host\b|test|bridge\b|"
              r"[A-Za-z0-9.\-]*\.(?:example|test|invalid|localhost)\b|example\.(?:com|org|net)\b)"
              r"[A-Za-z0-9.\-]+",
        description="Plaintext HTTP endpoint to a non-loopback host.",
        confidence=0.45,
        cvss=_cvss(ac="H", vc="L", vi="L"),
        allow_in_string=True,
        remediation="Use HTTPS. Pin the certificate for server-to-server MCP links.",
    ),
    Pattern(
        id="mcp.jwt.verification_disabled",
        category="identity_trust_forgery", layer=LAYER_MCP,
        regex=r"(?:jwt\.decode|decode_token|verify_jwt)\s*\([^)]*(?:verify\s*=\s*False|verify_signature\s*[\"']?\s*[:=]\s*False|options\s*=\s*\{[^}]*[\"']verify_signature[\"']\s*:\s*False)",
        description="JWT decoded with signature verification disabled.",
        confidence=0.95,
        cvss=_cvss(vc="H", vi="H", va="L", sc="H", si="H"),
        remediation="Always verify the signature. Reject unverified tokens outright.",
    ),
    Pattern(
        id="mcp.jwt.weak_secret",
        category="identity_trust_forgery", layer=LAYER_MCP,
        regex=(
            # the algorithm and the short secret may appear in either order
            r"(?:algorithm|alg)\s*[:=]\s*[\"']HS(?:256|384|512)[\"']"
            r"[\s\S]{0,160}?(?:secret|key)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{1,24}[\"']"
            r"|"
            r"(?:jwt_?secret|signing_?key)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{1,24}[\"']"
            r"[\s\S]{0,160}?(?:algorithm|alg)\s*[:=]\s*[\"']HS(?:256|384|512)[\"']"
        ),
        description="HS256 signing with a short, likely hardcoded secret.",
        confidence=0.80, ignorecase=True,
        cvss=_cvss(ac="H", vc="H", vi="H"),
        allow_in_string=True,
        remediation="Use an asymmetric algorithm, or a 256-bit secret from a secret manager.",
    ),
    Pattern(
        id="mcp.agent_card.auto_verified",
        category="identity_trust_forgery", layer=LAYER_MCP,
        regex=r"\bis_verified\s*[:=]\s*True\b|[\"']is_verified[\"']\s*:\s*(?:True|true)",
        description="Verification flag set without an issuer check.",
        confidence=0.65, allow_in_string=True,   # is_verified is usually a dict key
        cvss=_cvss(vc="H", vi="H", sc="H", si="H"),
        remediation="Set is_verified only after validating a signature chain to a trust authority.",
    ),
    Pattern(
        id="mcp.audit_log.mutable",
        category="audit_integrity", layer=LAYER_MCP,
        regex=r"(?:DELETE\s+FROM|UPDATE)\s+[\"'`]?audit_?logs?[\"'`]?\b|\.(?:delete|update)\s*\(\s*[\"']audit_?logs?[\"']",
        description="Audit log table mutated or deleted.",
        confidence=0.90, ignorecase=True,
        cvss=_cvss(pr="L", vi="H", si="H"),
        allow_in_string=True,
        remediation="Make audit storage append-only. Hash-chain entries so tampering is detectable.",
    ),
    Pattern(
        id="mcp.docker.privileged",
        category="container_escape", layer=LAYER_MCP,
        regex=r"privileged[\"']?\s*[:=]\s*(?:True|true)|--privileged\b|/var/run/docker\.sock",
        description="Privileged container or Docker socket mount.",
        confidence=0.85,
        cvss=_cvss(pr="L", vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
        allow_in_string=True,
        remediation="Never grant privileged mode or mount docker.sock into agent-deployed services.",
    ),
    Pattern(
        id="mcp.supply_chain.pipe_to_shell",
        category="supply_chain", layer=LAYER_MCP,
        # The pipe is escaped. The previous version treated it as regex alternation,
        # which made ' sh' match the word "should" and produced 2061 findings on
        # clean code. See benchmark/README.md.
        regex=r"\b(?:curl|wget)\b[^\r\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b",
        description="Remote script piped directly into a shell.",
        confidence=0.85,
        cvss=_cvss(vc="H", vi="H", va="H"),
        allow_in_string=True,
        remediation="Download, verify a checksum or signature, then execute.",
    ),
    Pattern(
        id="mcp.supply_chain.unpinned_install",
        category="supply_chain", layer=LAYER_MCP,
        regex=r"\b(?:pip|pip3)\s+install\s+(?:--\S+\s+)*(?:git\+|https?://)|\bnpm\s+(?:i|install)\s+\S+@latest\b",
        description="Dependency installed from an unpinned or non-registry source.",
        confidence=0.50,
        cvss=_cvss(ac="H", vi="H", si="L"),
        allow_in_string=True,
        remediation="Pin to a version and a hash. Install from a vetted registry.",
    ),
    Pattern(
        id="mcp.replay.no_nonce",
        category="message_replay", layer=LAYER_MCP,
        regex=r"def\s+(?:send|handle|receive|process)_message\s*\([^)]*\)[\s\S]{0,400}?(?=\bdef\b|\Z)(?<!nonce)(?<!timestamp)",
        description="Message handler with no visible freshness check. Heuristic, verify manually.",
        confidence=0.25,
        cvss=_cvss(ac="H", vi="L", si="L"),
        remediation="Bind a nonce or timestamp to each message and reject duplicates.",
    ),
    Pattern(
        id="mcp.session_cache.no_tenant_scope",
        category="cross_tenant_context_bleed", layer=LAYER_MCP,
        # Algorithm 3: a session or context cache keyed by something that is not
        # bound to the tenant, so one tenant's context can be served to another.
        regex=(
            # a session/context cache subscripted by a key with no tenant in it
            r"(?:session|context|tenant|request)\w*cache\s*\[\s*"
            r"(?![^\]]*(?:tenant|customer|org|account|user)\w*(?:id|key))[^\]]{0,80}\]"
            r"|"
            # any cache subscripted by a fixed, process-wide key
            r"\w*cache\s*\[\s*['\"](?:session|context|current|global|default)['\"]\s*\]"
            r"|"
            # a process-wide context/session store held in a global
            r"\bglobal_(?:context|cache|session|state)\b"
        ),
        description=("Session or context cache keyed without tenant scoping. Under "
                     "concurrent load one tenant's cached context can be returned to "
                     "another."),
        confidence=0.60, allow_in_string=True,
        cvss=_cvss(av="N", ac="H", pr="L", vc="H", vi="L", sc="H"),
        remediation=("Key the cache on a composite, cryptographically distinct "
                     "tenant identifier, and assert the tenant on read as well as "
                     "on write."),
    ),
    Pattern(
        id="mcp.session_cache.module_level_context",
        category="cross_tenant_context_bleed", layer=LAYER_MCP,
        regex=r"(?m)^(?:_?(?:session|context|conversation|memory)_?(?:store|cache|state|map))"
              r"\s*(?::\s*[^=\r\n]+)?=\s*(?:\{\s*\}|dict\(\s*\)|\[\s*\])",
        description=("Module-level mutable session or context store shared across all "
                     "requests, with no per-tenant partition."),
        confidence=0.55,
        cvss=_cvss(av="N", ac="H", pr="L", vc="H", sc="L"),
        remediation=("Scope the store per tenant, or move it behind an accessor that "
                     "requires a tenant identifier."),
    ),
    Pattern(
        id="mcp.tool_poisoning.description_sink",
        category="tool_poisoning", layer=LAYER_MCP,
        regex=r"(?:tool|function)[_\.]?(?:description|schema|manifest)\s*[:=]\s*(?:[a-z_]+\.(?:get|read|fetch|text|json)\s*\(|requests\.|await\s+fetch)",
        description="Tool description or schema sourced from a remote, untrusted value.",
        confidence=0.70, ignorecase=True,
        cvss=_cvss(ui="P", vc="H", vi="H", sc="H", si="H"),
        remediation="Treat tool metadata as untrusted input. Pin schemas and diff them on change.",
    ),

    # ------------------------------------------------------------------ Agentic AI layer
    Pattern(
        id="agent.trust_score.not_enforced",
        category="trust_enforcement", layer=LAYER_AGENT,
        regex=r"trust(?:_score)?\s*=\s*(?:max|min)?\s*\(?[^\r\n]*[-*/]\s*\d|def\s+\w*(?:decay|extend_delegation)\w*\s*\(",
        description="Trust score computed or decayed. Verify it is enforced as an authorisation floor.",
        confidence=0.35,
        cvss=_cvss(pr="L", vc="H", vi="H"),
        remediation="Compare the score against a minimum threshold before authorising the action.",
    ),
    Pattern(
        id="agent.memory.unscoped_query",
        category="cross_agent_memory", layer=LAYER_AGENT,
        regex=(
            # A vector or memory store, not a relational handle: db.query and
            # pool.query are SQL calls and belong to the sql_injection rule.
            r"\b(?!re\.)\w*(?:memory|vector|embedding|index|collection)\w*"
            r"\.(?:search|query|similarity_search)\s*\("
            r"(?![^)]*(?:agent_id|tenant|namespace|owner|scope|filter))"
            r"[^)]{0,120}\)"
        ),
        description="Vector or memory search with no agent/tenant scoping in the call.",
        confidence=0.55, ignorecase=True,
        cvss=_cvss(pr="L", vc="H"),
        remediation="Enforce agent_id or tenant scoping at the query layer, not in application code.",
    ),
    Pattern(
        id="agent.excessive_agency.unsandboxed_tool",
        category="excessive_agency", layer=LAYER_AGENT,
        regex=r"tools\s*=\s*\[[^\]]*(?:ShellTool|PythonREPL|BashProcess|FileWriteTool|os\.system|subprocess)",
        description="Agent granted shell, REPL or filesystem-write tools directly.",
        confidence=0.80,
        cvss=_cvss(ui="P", vc="H", vi="H", va="L", sc="H", si="H"),
        remediation="Sandbox tool execution and require explicit approval for write and shell actions.",
    ),
    Pattern(
        id="agent.goal_integrity.unsigned_update",
        category="goal_integrity", layer=LAYER_AGENT,
        regex=r"def\s+(?:update|set|modify)_goal\s*\([^)]*\)(?![\s\S]{0,300}?(?:verify|signature|sign|hmac|integrity))",
        description="Goal mutation path with no integrity or signature check nearby.",
        confidence=0.45,
        cvss=_cvss(pr="L", vi="H", si="H"),
        remediation="Sign goal updates and verify the signer before applying a change.",
    ),

    # ------------------------------------------------------------------ LLM layer
    Pattern(
        id="llm.prompt_injection.concat_user_input",
        category="prompt_injection", layer=LAYER_LLM,
        regex=r"(?:system_prompt|system_message|messages|prompt)\s*(?:=|\+=)\s*[^\r\n]*(?:\+\s*(?:user_input|user_message|request\.|query|body)|f[\"'][^\"']*\{(?:user_input|user_message|query)\})",
        description="Untrusted input concatenated into a system prompt.",
        confidence=0.75,
        cvss=_cvss(ui="P", vc="L", vi="H", si="L"),
        remediation="Keep untrusted text in a user-role message. Never interpolate it into system instructions.",
    ),
    Pattern(
        id="llm.indirect_injection.decoded_context",
        category="indirect_prompt_injection", layer=LAYER_LLM,
        regex=r"(?:context|prompt|messages)\s*(?:=|\+=|\.append\s*\()\s*(?:base64\.b64decode|requests\.get|scrape|fetch_url|crawl)\s*\(",
        description="Model context populated directly from a fetched or decoded remote source.",
        confidence=0.65,
        cvss=_cvss(ui="P", vi="H", si="L"),
        remediation="Delimit and label retrieved content. Scan for instruction-like text before use.",
    ),
]


def by_id() -> Dict[str, Pattern]:
    return {p.id: p for p in PATTERNS}


def categories() -> Dict[str, str]:
    """category -> layer"""
    return {p.category: p.layer for p in PATTERNS}


def validate() -> List[str]:
    """Return a list of problems with the pattern set. Empty list means healthy.

    Guards against the three defects measured in the previous version: duplicate
    ids silently overwriting each other, uncompilable regexes, and unescaped
    shell pipes being read as alternation.
    """
    problems = []
    seen = set()
    for p in PATTERNS:
        if p.id in seen:
            problems.append(f"duplicate pattern id: {p.id}")
        seen.add(p.id)
        try:
            p.compiled()
        except re.error as exc:
            problems.append(f"{p.id}: uncompilable regex: {exc}")
        if not 0.0 <= p.confidence <= 1.0:
            problems.append(f"{p.id}: confidence out of range: {p.confidence}")
        if p.layer not in (LAYER_LLM, LAYER_AGENT, LAYER_MCP, LAYER_WEB):
            problems.append(f"{p.id}: unknown layer: {p.layer}")
        # A shell pipe written unescaped is alternation. This is the bug that
        # produced 2061 false positives on clean code.
        for shell_cmd in ("curl ", "wget ", "cat ", "echo "):
            if shell_cmd in p.regex and re.search(r"(?<!\\)(?<!\[\^)\|(?!\s*\\\|)", p.regex):
                if r"\|" not in p.regex:
                    problems.append(
                        f"{p.id}: shell command with an unescaped '|'. "
                        f"In a regex '|' is alternation, not a pipe."
                    )
    return problems
