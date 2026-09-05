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
    # File-level gates. ``requires`` is a regex that must match somewhere in the
    # file for the rule to run; ``absent`` is one that must match nowhere. A
    # single-site regex cannot say "this file defines MCP tools" or "this file
    # never canonicalises a path"; these can.
    requires: str = ""
    absent: str = ""

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


# Files that define or serve MCP tools. Used as a ``requires`` gate by rules whose
# evidence is only meaningful in that context: an HTTP fetch of a caller-supplied
# URL is a vulnerability in a tool and a feature in an HTTP client library.
MCP_TOOL_CONTEXT = (
    r"@(?:mcp|server|app|self\.mcp)\.tool\b|\.tool\(\s*[\"'{]|@tool\b|def call_tool"
    r"|list_tools|McpServer|FastMCP|MCPServer|registerTool|@server\.call_tool"
    r"|ModelContextProtocol|from mcp\.|from \"@modelcontextprotocol"
)

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
        # Nested parentheses are allowed before shell=True: on a real server the
        # call was subprocess.run(subprocess.list2cmdline(cmd), ..., shell=True) and
        # the earlier [^)]* stopped at the inner ')'. asyncio.create_subprocess_shell
        # is the same sink by another name.
        regex=(
            r"\bsubprocess\.(?:run|call|check_output|Popen|check_call)\s*"
            r"\((?:[^()]|\([^()]*\))*shell\s*=\s*True"
            r"|\basyncio\.create_subprocess_shell\s*\("
            r"|\bos\.popen\s*\(\s*(?:f[\"']|[^)]*\+)"
        ),
        description=("A command string handed to a shell: subprocess with shell=True, "
                     "asyncio.create_subprocess_shell, or os.popen on a built string."),
        confidence=0.70,
        cvss=_cvss(vc="H", vi="H", va="H"),
        remediation="Pass an argument list and drop the shell.",
    ),
    Pattern(
        id="web.sql_injection.format",
        category="sql_injection", layer=LAYER_WEB,
        # Measured on 55 third-party MCP servers this rule produced 77 findings, of
        # which 74 were three idioms that are not injection: a placeholder list
        # built with ','.join('?' * n), an UPPER_CASE constant for a table or column
        # name, and a '%' inside a quoted string (strftime('%s')) read as the
        # formatting operator. Each is now excluded explicitly.
        regex=(
            r"\b(?:execute|executemany|executescript)\s*\(\s*"
            r"(?:"
            # "..." % x   "..." + x   "...".format(   with the closing quote matched
            # to the opening one, so a quote of the other kind inside is not a close
            # '+ "literal"' and '+ UPPER_CASE_CONSTANT' are statement assembly, not
            # user data
            r"([\"'])(?:(?!\1).)*\1\s*(?:%(?!\s*[\"'])|\+\s*(?![\s\"']|[A-Z_][A-Z0-9_]*\b)"
            r"|\.format\s*\()"
            r"|"
            # f-string DML whose placeholder is not a known-safe idiom
            r"f([\"']{1,3})\s*(?i:SELECT|INSERT|UPDATE|DELETE|WITH|REPLACE|MERGE)\b"
            r"(?:(?!\2)[\s\S]){0,400}?"
            r"\{(?!\s*(?:[A-Z_][A-Z0-9_]*"                    # UPPER_CASE constant
            r"|[\w.]*(?:placeholders?|qmarks|marks)"            # ?,?,? list
            r"|[\"'][?,\s]*[\"']\s*\.join\([^}]*"               # ','.join('?'...)
            r"|_?(?:table|tbl|column|col|field|columns|cols)(?:_name)?"  # identifier
            r")\s*\})"
            r")"
            r"|"
            # JavaScript and TypeScript: db.query("SELECT ..." + x) or a template
            # literal with ${...} inside a statement
            r"\.(?:query|execute|raw|exec)\s*\(\s*"
            r"(?:[\"'][^\"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^)]{0,160}?[\"']\s*\+\s*"
            r"(?![\s\"']|[A-Z_][A-Z0-9_]*\b)"
            r"|`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^`]{0,300}?\$\{)"
        ),
        description="SQL statement built by string formatting or concatenation.",
        confidence=0.85,
        cvss=_cvss(vc="H", vi="H", va="L"),
        remediation="Use parameterised queries. Never format user input into SQL.",
    ),
    Pattern(
        id="web.sql_injection.identifier_format",
        category="sql_injection", layer=LAYER_WEB,
        # A table, column, setting or extension name interpolated into a statement
        # that cannot take a bound parameter (SET, SAVEPOINT, INSTALL, ALTER...).
        # Real only if the name is caller-controlled, which a static rule cannot
        # tell, so this is informational.
        regex=(
            r"\b(?:execute|executescript)\s*\(\s*f([\"']{1,3})\s*"
            r"(?i:SAVEPOINT|ROLLBACK|RELEASE|INSTALL|LOAD|SET|PRAGMA|CREATE|ALTER|DROP"
            r"|ATTACH|DETACH|VACUUM|GRANT|REVOKE|TRUNCATE)\b"
            r"(?:(?!\1)[\s\S]){0,300}?\{(?!\s*[A-Z_][A-Z0-9_]*\s*\})"
        ),
        description=("A SQL identifier is interpolated into a statement that cannot take "
                     "a bound parameter. Safe only if the name comes from an allow-list."),
        confidence=0.45,
        cvss=_cvss(ac="H", vc="L", vi="L"),
        remediation="Validate the identifier against an allow-list before interpolating it.",
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
        # MD5 or SHA-1 where the surrounding code is doing something security-
        # relevant. The bare call is a separate, informational rule: on real
        # servers 14 of 15 uses were content fingerprints and cache keys.
        regex=(
            # "token" alone is not in the list: an embedding service hashing text
            # tokens is not hashing a credential.
            r"(?i:password|passwd|access_token|auth_token|session_token|api_token|csrf"
            r"|secret|signature|credential|hmac|session_key|api_key|auth)"
            r"[^\n]{0,80}\bhashlib\.(?:md5|sha1)\s*\("
            r"|\bhashlib\.(?:md5|sha1)\s*\([^)\n]*"
            r"(?i:password|passwd|access_token|auth_token|session_token|api_token"
            r"|secret|credential|session_key|api_key)"
            r"|\bMessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']"
        ),
        description="Broken hash used where a cryptographic hash is expected.",
        confidence=0.70,
        cvss=_cvss(vi="L"),
        remediation="Use SHA-256 or better. For passwords use argon2 or bcrypt.",
    ),
    Pattern(
        id="web.weak_crypto.hash_fingerprint",
        category="weak_crypto", layer=LAYER_WEB,
        regex=r"\bhashlib\.(?:md5|sha1)\s*\(",
        description=("MD5 or SHA-1 in use. Fine for a content fingerprint or cache key; "
                     "not fine if the value protects anything."),
        confidence=0.40,
        cvss=_cvss(ac="H", vi="L"),
        remediation="If this guards integrity or identity, move to SHA-256.",
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
            # child_process / Function constructor. The look-behinds and the typed
            # parameter check exclude a *definition* named exec, such as
            # `protected exec(sql: string)`.
            r"(?:^|[^.\w])"
            r"(?<!def )(?<!function )(?<!async )(?<!static )(?<!public )"
            r"(?<!private )(?<!protected )"
            r"(?:eval|exec)\s*\(\s*"
            r"(?![\"']\s*\))"
            r"(?!\w+\s*:\s*\w)"
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
    Pattern(
        id="web.cmd_injection.js_exec_interpolated",
        category="command_injection", layer=LAYER_WEB,
        # CVE-2025-53355 (mcp-server-kubernetes), CVE-2025-53967 (Framelink Figma),
        # CVE-2026-0755 (gemini-mcp-tool), CVE-2025-54994: a template literal or a
        # concatenation handed to exec/execSync. The bare-call form excludes
        # RegExp.prototype.exec by requiring no '.' before the name.
        regex=(
            r"(?:(?:^|[^\w.$])(?:execSync|exec|execAsync|execPromise)"
            r"|\bchild_process\.(?:exec|execSync))"
            r"\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"'\n]*[\"']\s*\+\s*\w)"
        ),
        description=("A shell command built from a template literal or concatenation "
                     "and handed to exec. This is the pattern behind most of the 2026 "
                     "MCP command-injection CVEs."),
        confidence=0.85,
        cvss=_cvss(vc="H", vi="H", va="H", sc="H", si="H", sa="H"),
        remediation="Use execFile or spawn with an argument array. Never build a shell string.",
    ),
    Pattern(
        id="web.cmd_injection.spawn_shell_true",
        category="command_injection", layer=LAYER_WEB,
        regex=r"\bspawn(?:Sync)?\s*\((?:[^()]|\([^()]*\))*shell\s*:\s*true",
        description="spawn invoked with shell: true, so its arguments are parsed by a shell.",
        confidence=0.70,
        cvss=_cvss(vc="H", vi="H", va="H"),
        remediation="Drop shell: true and pass arguments as an array.",
    ),
    Pattern(
        id="web.argument_injection.cli_list",
        category="argument_injection", layer=LAYER_WEB,
        # CVE-2025-68144 (Anthropic mcp-server-git): repo.git.diff(f"--unified=..",
        # target) let a target beginning with '-' be read as a git option. An
        # argument list avoids the shell but not this. The look-ahead exempts lists
        # that pass "--" before the caller's values.
        regex=(
            r"(?:\bsubprocess\.(?:run|call|check_output|check_call|Popen)"
            r"|\bexecFile(?:Sync)?|\bspawn(?:Sync)?|\bexeca)\s*\(\s*\[\s*"
            r"[\"'](?:git|kubectl|docker|ssh|scp|rsync|curl|wget|tar|find|openssl"
            r"|ffmpeg|ffprobe|gh|npm|npx|pip|psql|mysql|helm|terraform|aws|gcloud|az)[\"']"
            # An f-string counts only when the placeholder *starts* the argument:
            # f"--unified={n}" is an option with a value, f"{target}" is the value.
            r"(?![^\]]*[\"']--[\"'])[^\]]*?"
            r"(?:f[\"']\{|\$\{|\+\s*\w"
            r"|\b(?:arguments|args|params|input|query|target|user_\w+|request\.\w+)\b)"
            # JavaScript puts the program before the list: execFile("git", [...])
            r"|(?:execFile(?:Sync)?|spawn(?:Sync)?|execa)\s*\(\s*"
            r"[\"'](?:git|kubectl|docker|ssh|scp|rsync|curl|wget|tar|find|openssl"
            r"|ffmpeg|ffprobe|gh|npm|npx|pip|psql|mysql|helm|terraform|aws|gcloud|az)[\"']"
            r"\s*,\s*\[(?![^\]]*[\"']--[\"'])[^\]]*?"
            r"(?:\$\{|\+\s*\w|\b(?:arguments|args|params|input|query|target|user_\w+)\b)"
            r"|\brepo\.git\.\w+\s*\((?![^)]*[\"']--[\"'])(?:[^()]|\([^()]*\))*"
            r"(?:f[\"']\{|\+\s*\w|\b(?:arguments|args|params|target|path)\b)"
        ),
        # Anthropic's fixed git server rejects option-shaped values three lines
        # above the call the rule matches. A file that checks for a leading '-'
        # anywhere has seen this class and is left alone.
        absent=r"startswith\([\"']-[\"']\)|startsWith\([\"']-[\"']\)",
        description=("A caller-supplied value is passed to a command-line program without "
                     "a '--' separator, so a value starting with '-' is read as an option."),
        confidence=0.60,
        cvss=_cvss(ac="L", pr="N", ui="N", vc="H", vi="H", va="L"),
        remediation=("Insert '--' before caller-supplied arguments and reject values that "
                     "start with '-'."),
    ),
    Pattern(
        id="web.path_traversal.startswith_containment",
        category="path_traversal", layer=LAYER_WEB,
        # CVE-2025-66689 (Zen MCP), CVE-2025-53109/53110 (filesystem server): a
        # string-prefix check as the only containment test. '/data' is a prefix of
        # '/data_evil', and a symlink inside the root points anywhere. Suppressed
        # when the file canonicalises paths somewhere.
        regex=(
            # Paths only. A redirect-URI or origin prefix check is a different
            # control and produced the only false positives on real servers.
            r"(?<!uri)(?<!url)(?<!URI)(?<!URL)"
            r"\.startswith\(\s*(?:str\(\s*)?(?:self\.)?\w*"
            r"(?i:allowed|base|root|safe|sandbox|workspace|permitted|jail)"
            r"(?!\w*(?i:redirect|uri|url|origin|host|scheme))\w*"
        ),
        absent=(r"realpath|\.resolve\(|abspath|relative_to|normpath|commonpath"
                r"|is_relative_to|path\.normalize"),
        description=("Path containment checked with a string prefix and no "
                     "canonicalisation, which '..' segments and symlinks bypass."),
        confidence=0.60,
        cvss=_cvss(vc="H", vi="L"),
        remediation=("Resolve with realpath (or Path.resolve) first, then compare with "
                     "os.path.commonpath or Path.is_relative_to."),
    ),
    Pattern(
        id="web.ssrf.tool_argument_url",
        category="ssrf", layer=LAYER_WEB,
        # CVE-2025-65513 (mcp-fetch-server), CVE-2026-26118 (Azure MCP),
        # CVE-2026-27826 (mcp-atlassian), TRA-2025-36 (Microsoft Learn MCP): a tool
        # fetches the address it is given. Runs only in files that define MCP tools
        # and contain no visible SSRF defence, because in a generic HTTP wrapper
        # fetch(url) is the whole point.
        regex=(
            r"\b(?:requests\.(?:get|post|put|patch|delete|head|request)"
            r"|httpx\.(?:get|post|put|patch|delete|request)"
            r"|urllib\.request\.urlopen|urlopen|fetch"
            r"|axios(?:\.(?:get|post|put|patch|delete|request))?|got"
            r"|(?:client|session|http|c|s|self\.(?:client|session|_client|http))"
            r"\.(?:get|post|fetch|request))"
            # No f-string form: on real servers f"/api/notes/{id}" on a fixed base
            # URL was 33 of 41 hits, and a fixed host is not SSRF.
            r"\s*\(\s*(?:(?:arguments|args|params|input|request|req|body|payload|options|opts)"
            r"\s*(?:\[\s*[\"']|\.)\s*(?:url|uri|endpoint|link|href|target|address|host|webhook)\w*"
            r"|(?:url|uri|endpoint|link|href|target_url|remote_url|image_url|webhook_url"
            r"|source_url|feed_url)\s*[,)])"
        ),
        requires=MCP_TOOL_CONTEXT,
        absent=(r"is_private|private_ip|ip_address\(|allow_?list|whitelist|validate_url"
                r"|safe_url|_guarded_fetch|ssrf|allowed_hosts|ALLOWED_HOSTS|allowed_domains"
                r"|ALLOWED_DOMAINS|urlparse\([^)]*\)\.(?:hostname|netloc)"),
        description=("An MCP tool fetches a caller-supplied URL with no host allow-list or "
                     "private-address check, so it can be pointed at internal services "
                     "and cloud metadata endpoints."),
        confidence=0.55,
        cvss=_cvss(av="N", ac="L", pr="N", ui="N", vc="H", vi="L", sc="H"),
        remediation=("Resolve the host, reject private and link-local ranges, disable "
                     "redirects or re-check after each one, and prefer an allow-list."),
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
            # any cache subscripted by a fixed, process-wide key. The identifier
            # prefix is bounded: an unbounded \w* in front of a literal is
            # quadratic, and a 2 MB single-line file made it hang for ten minutes.
            r"\b\w{0,40}cache\s*\[\s*['\"](?:session|context|current|global|default)['\"]\s*\]"
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
        id="mcp.line_jumping.instructions_in_tool_description",
        category="line_jumping", layer=LAYER_MCP,
        # Trail of Bits, "Jumping the line" (2025). A malicious server puts
        # imperative text in a tool *description*. The model reads descriptions when
        # the tool list loads, so this acts before any tool is called.
        regex=(
            r"(?is)[\"']?(?:description|instructions?|title)[\"']?\s*[:=]\s*"
            r"[\"'`][^\"'`]{0,400}?"
            r"(?:<IMPORTANT>|<SECRET>|<system>"
            r"|ignore (?:all |any )?(?:previous|prior|above)"
            r"|do not (?:tell|mention|inform|reveal)"
            r"|before (?:using|calling|invoking) this tool"
            r"|you must (?:first|always)"
            r"|instead of (?:calling|using))"
        ),
        description=("A tool description contains imperative instructions. Models read "
                     "descriptions when the tool list loads, so this acts before the "
                     "tool is ever called."),
        confidence=0.80, allow_in_string=True,
        cvss=_cvss(av="N", ac="L", pr="N", ui="N", vc="H", vi="H", sc="H", si="H"),
        remediation=("Treat tool metadata as untrusted data rather than as "
                     "instructions. Show users the full description and pin it so "
                     "changes are visible."),
    ),
    Pattern(
        id="mcp.tool_shadowing.cross_tool_directive",
        category="tool_shadowing", layer=LAYER_MCP,
        # In a multi-server session every tool description shares one context, so a
        # description that gives directions about another tool can redirect it.
        regex=(
            r"(?is)[\"']?description[\"']?\s*[:=]\s*[\"'`][^\"'`]{0,400}?"
            r"(?:when (?:the user |you )?(?:calls?|uses?|invokes?) (?:the )?[\w.]+ tool"
            r"|for (?:all|any) (?:other )?tools?"
            r"|applies to (?:every|all) tool"
            r"|override[s]? the [\w.]+ tool)"
        ),
        description=("A tool description gives directions about a different tool. All "
                     "descriptions share one context, so this can redirect a tool the "
                     "user trusts."),
        confidence=0.75, allow_in_string=True,
        cvss=_cvss(av="N", ac="L", pr="N", ui="P", vc="H", vi="H", sc="H", si="H"),
        remediation=("Namespace tools per server and reject metadata from one server "
                     "that references another's tools."),
    ),
    Pattern(
        id="mcp.hidden_unicode.invisible_instruction",
        category="hidden_instruction", layer=LAYER_MCP,
        # Zero-width and bidi-override characters carry text a reviewer cannot see
        # but a model still reads. Anchored to the line start so the guard sees the
        # whole line: code that *strips* these characters names them, and on real
        # servers that is where the rule fired. A leading byte-order mark is
        # removed by the analyzer before matching.
        regex=(
            r"(?im)^(?!.*(?:strip|sanitis|sanitiz|remove|replace|filter|normali[sz]"
            r"|ord\(|ZWSP|ZWNJ|ZWJ|BOM|zero.width|word.joiner|invisible|bidi"
            r"|\\u20|\\ufeff|u\+20|u\+feff))"
            r".*[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]"
        ),
        description=("Invisible Unicode: zero-width or bidirectional-override "
                     "characters. A reviewer cannot see these; a model still reads "
                     "them."),
        confidence=0.70, code_only=False, allow_in_string=True,
        cvss=_cvss(av="N", ac="L", pr="N", ui="N", vc="H", vi="H", sc="L", si="L"),
        remediation=("Strip characters outside the expected script from tool metadata "
                     "and from any text that reaches a model."),
    ),
    Pattern(
        id="mcp.dns_rebinding.protection_disabled",
        category="dns_rebinding", layer=LAYER_MCP,
        # CVE-2025-66414 (TypeScript SDK) and CVE-2025-66416 (Python SDK): the
        # SDKs now enable this by default for localhost servers. Turning it off is
        # an explicit choice and the exposure is exactly the one the CVEs describe.
        regex=(r"enable_dns_rebinding_protection\s*=\s*False"
               r"|enableDnsRebindingProtection\s*:\s*false"),
        description=("DNS-rebinding protection explicitly disabled on an HTTP transport, "
                     "so a web page in the user's browser can reach this server."),
        confidence=0.80,
        cvss=_cvss(av="N", ac="L", pr="N", ui="P", vc="H", vi="H", sc="L", si="L"),
        remediation=("Leave protection on and list the hosts and origins that are "
                     "genuinely expected in allowed_hosts / allowed_origins."),
    ),
    Pattern(
        id="mcp.dns_rebinding.http_transport_unconfigured",
        category="dns_rebinding", layer=LAYER_MCP,
        # An HTTP or SSE transport with no transport-security settings anywhere in
        # the file. Recent SDKs protect localhost by default, so this is a review
        # item rather than a defect: informational.
        regex=(r"\.run\(\s*transport\s*=\s*[\"'](?:sse|streamable-http|http)[\"']"
               r"|\.(?:sse_app|streamable_http_app)\(\s*\)"
               r"|new\s+(?:SSEServerTransport|StreamableHTTPServerTransport)\s*\("),
        absent=(r"TransportSecuritySettings|transport_security|security_settings"
                r"|allowed_hosts|enable_dns_rebinding_protection"
                r"|enableDnsRebindingProtection|allowedHosts|allowedOrigins"),
        description=("HTTP transport started with no transport-security settings in "
                     "this file. Confirm the SDK version enables DNS-rebinding "
                     "protection by default, or set it explicitly."),
        confidence=0.45,
        cvss=_cvss(av="N", ac="H", pr="N", ui="P", vc="L", vi="L"),
        remediation="Configure TransportSecuritySettings / enableDnsRebindingProtection.",
    ),
    Pattern(
        id="mcp.network_exposure.bind_all_interfaces",
        category="network_exposure", layer=LAYER_MCP,
        # CVE-2026-23744 (MCPJam Inspector) and CVE-2025-49596 (MCP Inspector):
        # listening on 0.0.0.0 with no authentication. Runs only in files that
        # define MCP tools and show no sign of an auth check.
        regex=(r"(?:\bhost\s*[=:]\s*|\.host\s*=\s*|listen\(\s*\w+\s*,\s*)"
               r"[\"']0\.0\.0\.0[\"']"),
        requires=MCP_TOOL_CONTEXT,
        absent=(r"(?i)\bauth|bearer|api[_-]?key|access_token|verify_token|require_auth"
                r"|middleware"),
        description=("Server binds every network interface and this file shows no "
                     "authentication, so anyone who can reach the host can call its tools."),
        confidence=0.55,
        cvss=_cvss(av="N", ac="L", pr="N", ui="N", vc="H", vi="H", va="L"),
        remediation=("Bind 127.0.0.1 unless remote access is intended; if it is, put "
                     "authentication in front of the transport."),
    ),
    Pattern(
        id="mcp.session.shared_http_transport",
        category="cross_tenant_context_bleed", layer=LAYER_MCP,
        # CVE-2026-25536 (TypeScript SDK): one StreamableHTTPServerTransport reused
        # across clients leaked one client's data to another. A module-level
        # transport is by construction shared by every request.
        regex=(r"(?m)^(?:export\s+)?(?:const|let|var)\s+\w+\s*(?::\s*\w+)?\s*=\s*"
               r"new\s+(?:StreamableHTTPServerTransport|SSEServerTransport)\s*\("),
        description=("A single HTTP transport instance created at module level is "
                     "shared by every client that connects."),
        confidence=0.60,
        cvss=_cvss(av="N", ac="H", pr="L", vc="H", sc="L"),
        remediation="Create the transport inside the request handler, one per session.",
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
        id="agent.excessive_agency.shell_argv",
        category="excessive_agency", layer=LAYER_AGENT,
        # ["bash", "-lc", command] is shell=True by another route: the list form
        # avoids nothing when the list's job is to start a shell on a value the
        # caller chose.
        regex=(r"\[\s*[\"'](?:/bin/|/usr/bin/)?(?:bash|sh|zsh|dash|cmd(?:\.exe)?"
               r"|powershell(?:\.exe)?|pwsh)[\"']\s*,\s*"
               r"[\"'](?:-l?c|-Command|-c|/c)[\"']\s*,\s*(?=[A-Za-z_(])"),
        description=("A shell is started on a non-literal command string via an argument "
                     "list, which hands whoever controls that string a shell."),
        confidence=0.75,
        cvss=_cvss(ui="P", vc="H", vi="H", va="L", sc="H", si="H"),
        remediation=("Do not expose a general shell as a tool. If a command must run, "
                     "pass a fixed program and validated arguments, without a shell."),
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
        for gate_name in ("requires", "absent"):
            gate = getattr(p, gate_name)
            if gate:
                try:
                    re.compile(gate)
                except re.error as exc:
                    problems.append(f"{p.id}: uncompilable {gate_name} gate: {exc}")
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
