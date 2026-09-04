"""Configuration, including the threat-intelligence source list.

These URLs were previously a literal Python list inside ``cli.py``. Moving them
here means they can be overridden without editing code:

    export MCPVULN_INTEL_SOURCES=/path/to/sources.txt   # one URL per line
"""

from __future__ import annotations

import io
import os
from typing import List

DEFAULT_INTEL_SOURCES: List[str] = [
    "https://github.com/invariantlabs-ai/mcp-scan",
    "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
    "https://invariantlabs.ai/blog/whatsapp-mcp-exploited",
    "https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe",
    "https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/",
    "https://hiddenlayer.com/innovation-hub/exploiting-mcp-tool-parameters/",
    "https://www.backslash.security/blog/hundreds-of-mcp-servers-vulnerable-to-abuse",
    "https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls",
    "https://strobes.co/blog/mcp-model-context-protocol-and-its-critical-vulnerabilities/",
    "https://vulnerablemcp.info/index.html",
    "https://unit42.paloaltonetworks.com/agentic-ai-threats/",
]


def intel_sources() -> List[str]:
    path = os.environ.get("MCPVULN_INTEL_SOURCES")
    if path and os.path.isfile(path):
        with io.open(path, encoding="utf-8") as fh:
            urls = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        if urls:
            return urls
    return list(DEFAULT_INTEL_SOURCES)
