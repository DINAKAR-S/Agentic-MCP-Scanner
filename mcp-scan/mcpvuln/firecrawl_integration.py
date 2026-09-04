"""External threat intelligence.

Fetches public advisories to give findings real-world context. Optional: a scan is
complete without it.

One behavioural fix from the previous version: a failed crawl used to be appended
to the results list as though it were a vulnerability, so network errors reached the
reporting stage disguised as findings. Failures are now logged and dropped.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional

from .config import intel_sources

log = logging.getLogger("mcpvuln.intel")


class ThreatIntelClient:
    def __init__(self, api_key: Optional[str] = None, sources: Optional[List[str]] = None,
                 max_sources: int = 10):
        self.api_key = api_key or os.environ.get("FIRECRAWL_API_KEY")
        self.sources = (sources if sources is not None else intel_sources())[:max_sources]

    def available(self) -> bool:
        return bool(self.api_key)

    def fetch(self) -> List[Dict[str, str]]:
        if not self.available():
            log.info("FIRECRAWL_API_KEY not set, skipping threat intelligence")
            return []

        from firecrawl import FirecrawlApp  # lazy import

        app = FirecrawlApp(api_key=self.api_key)
        results: List[Dict[str, str]] = []
        failures = 0

        try:
            search = app.search("MCP A2A LLM vulnerability", limit=10)
            for r in getattr(search, "data", []) or []:
                results.append({
                    "name": r.get("title") or "Untitled",
                    "description": (r.get("description") or "")[:200],
                    "source_url": r.get("url") or "",
                })
        except Exception as exc:
            failures += 1
            log.warning("threat-intel search failed: %s", exc)

        for url in self.sources:
            try:
                page = app.scrape_url(url, formats=["markdown"])
                results.append({
                    "name": getattr(page, "title", None) or url,
                    "description": (getattr(page, "description", "") or "")[:200],
                    "source_url": url,
                })
            except Exception as exc:
                # Dropped, not appended. A crawl failure is not a vulnerability.
                failures += 1
                log.warning("could not crawl %s: %s", url, exc)

        if failures:
            log.info("threat intelligence: %d sources retrieved, %d failed",
                     len(results), failures)
        return results


FirecrawlIntegrationAgent = ThreatIntelClient
