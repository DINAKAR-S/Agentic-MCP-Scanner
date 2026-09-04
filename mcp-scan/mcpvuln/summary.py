"""Business-facing summaries, generated deterministically.

Algorithm 2 of the design specifies two outputs that are not technical metrics:
a per-finding executive summary of two to three sentences aimed at a
non-specialist reader, and a top-line risk summary prepended for leadership.

Both are produced here by composition rather than by a language model, so they
are reproducible and can be quoted in an evaluation. A model may still add
commentary on top through ``--narrative``; that is separate and is never used
for anything measured.
"""

from __future__ import annotations

from typing import Dict, List

# What an attacker gains, in the reader's terms rather than the scanner's.
_IMPACT: Dict[str, str] = {
    "command_injection":
        "an attacker who can influence this input can run their own commands on the "
        "server",
    "sql_injection":
        "an attacker who can influence this input can read or alter the database "
        "behind it",
    "xss":
        "an attacker can run script in another user's browser session",
    "path_traversal":
        "an attacker can reach files outside the directory this code is meant to "
        "serve",
    "hardcoded_secrets":
        "a credential is stored in the source, so anyone with repository access has "
        "it, including anyone who ever cloned or forked the repository",
    "weak_crypto":
        "the protection here is broken rather than merely dated, so data it covers "
        "should be treated as unprotected",
    "insecure_random":
        "values that are meant to be unguessable are predictable",
    "unsafe_deserialization":
        "an attacker who controls this data can run code inside the process",
    "dynamic_code_execution":
        "an attacker who influences this value can run code inside the process",
    "insecure_transport":
        "traffic to this endpoint is unencrypted and can be read or altered in "
        "transit",
    "identity_trust_forgery":
        "an attacker can present a forged identity that the system accepts as "
        "genuine",
    "audit_integrity":
        "the record of what happened can be altered or erased, so an incident may "
        "not be reconstructable afterwards",
    "container_escape":
        "code running in this container can reach the host it runs on, and "
        "therefore everything else on that host",
    "supply_chain":
        "code is fetched and executed without being verified first, so whoever "
        "controls the source controls this system",
    "message_replay":
        "a captured message can be sent again and accepted as new",
    "tool_poisoning":
        "an untrusted source can change what a tool claims to do, and the model "
        "acts on that claim",
    "trust_enforcement":
        "a trust level is calculated but not enforced, so an action can proceed at "
        "a trust level that should have blocked it",
    "cross_agent_memory":
        "one agent can read another agent's stored context, including data it was "
        "never meant to see",
    "cross_tenant_context_bleed":
        "one customer's data can be served to another customer",
    "excessive_agency":
        "the model can act on the system directly, so a successful prompt attack "
        "becomes a real action rather than just a bad answer",
    "goal_integrity":
        "an agent's objective can be changed without that change being detectable",
    "prompt_injection":
        "untrusted text is placed where the model reads instructions, so an "
        "attacker can redirect what the agent does",
    "indirect_prompt_injection":
        "content fetched from elsewhere is treated as instructions, so an attacker "
        "who controls that content controls the agent",
}

_URGENCY = {
    "Immediate": "This needs attention now, ahead of planned work.",
    "Out-of-Band": "This warrants a fix outside the normal release cycle.",
    "Scheduled": "This should be scheduled into the normal release cycle.",
    "Defer": "This can be handled as routine maintenance.",
}

_CONFIDENCE_CAVEAT = (
    "The detector reports moderate confidence here, so confirm it against the "
    "surrounding code before acting."
)


def finding_summary(finding: dict) -> str:
    """Two to three sentences, business-facing, for one finding.

    Algorithm 2, step 6.
    """
    category = finding.get("category", "")
    impact = _IMPACT.get(category, "this weakness can be exploited by someone who "
                                   "can reach the affected code")
    severity = finding.get("cvss_severity", "None")
    score = finding.get("cvss_base_score", 0.0)
    priority = (finding.get("ssvc") or {}).get("priority", "Scheduled")
    where = finding.get("file", "the codebase")

    first = (f"In {where}, {impact}. ")
    second = (f"It is rated {severity.lower()} severity "
              f"(CVSS v4.0 {score}) with an SSVC priority of {priority}. ")
    third = _URGENCY.get(priority, "")

    out = first + second + third
    if float(finding.get("confidence", 1.0)) < 0.6:
        out += " " + _CONFIDENCE_CAVEAT
    return out.strip()


def leadership_summary(contract: dict) -> str:
    """Top-line risk summary, prepended for a non-technical reader.

    Algorithm 2, step 13.
    """
    scan = contract.get("scan", {})
    findings = [f for f in contract.get("findings", []) if not f.get("informational")]
    repo = contract.get("repository", "this repository")
    lines_scanned = scan.get("lines_scanned", 0)

    if not findings:
        return (f"No issues above the reporting threshold were found in {repo} "
                f"across {lines_scanned:,} lines. "
                f"{scan.get('findings_informational', 0)} lower-confidence "
                f"observations are listed separately and need manual review. "
                f"This is a static scan, so it is evidence of nothing obvious "
                f"rather than evidence of safety.")

    by_sev: Dict[str, int] = {}
    for f in findings:
        by_sev[f["cvss_severity"]] = by_sev.get(f["cvss_severity"], 0) + 1
    worst = next((s for s in ("Critical", "High", "Medium", "Low") if s in by_sev), "Low")

    immediate = [f for f in findings
                 if (f.get("ssvc") or {}).get("priority") == "Immediate"]
    top = findings[0]

    parts: List[str] = []
    counts = ", ".join(f"{n} {s.lower()}" for s, n in
                       sorted(by_sev.items(), key=lambda kv: -kv[1]))
    parts.append(f"{len(findings)} issues were found in {repo} across "
                 f"{lines_scanned:,} lines ({counts}).")
    parts.append(f"The most urgent is {top['category'].replace('_', ' ')} in "
                 f"{top['file']}, where {_IMPACT.get(top['category'], 'the code is exploitable')}.")
    if immediate:
        parts.append(f"{len(immediate)} of these carry an SSVC priority of Immediate "
                     f"and should be addressed ahead of planned work.")
    else:
        parts.append("None are rated Immediate, so these can be scheduled rather "
                     "than treated as an incident.")
    parts.append(f"Recommended next step: assign the {worst.lower()}-severity items "
                 f"to an owner and confirm each against the surrounding code, since "
                 f"static analysis cannot see how the data actually flows.")
    return " ".join(parts)
