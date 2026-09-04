"""Repository ingestion.

Wraps ``gitingest``. Previously this subclassed an agno ``Agent`` whose model and
search tool were constructed but never used; the class does no model work, so it is
now a plain object with no LLM dependency.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

log = logging.getLogger("mcpvuln.ingest")

_FILE_BLOCK_RE = re.compile(r"=+\nFILE: (.+?)\n=+\n")


class GitHubScraper:
    @staticmethod
    def parse_gitingest_content(content: str) -> Dict[str, str]:
        blocks = _FILE_BLOCK_RE.split(content)
        files: Dict[str, str] = {}
        for i in range(1, len(blocks) - 1, 2):
            files[blocks[i].strip()] = blocks[i + 1].strip()
        return files

    def scrape_github_repos(self, urls: List[str], *,
                            include_patterns=None, exclude_patterns=None,
                            max_file_size: Optional[int] = None,
                            token: Optional[str] = None) -> List[dict]:
        from gitingest import ingest  # lazy import

        results: List[dict] = []
        for url in urls:
            kwargs = {}
            if include_patterns is not None:
                kwargs["include_patterns"] = include_patterns
            if exclude_patterns is not None:
                kwargs["exclude_patterns"] = exclude_patterns
            if max_file_size is not None:
                kwargs["max_file_size"] = max_file_size
            if token is not None:
                kwargs["token"] = token
            try:
                summary, tree, content = ingest(url, **kwargs)
            except Exception as exc:
                log.error("failed to ingest %s: %s", url, exc)
                continue
            results.append({
                "url": url,
                "summary": summary,
                "tree": tree,
                "files": self.parse_gitingest_content(content),
            })
        return results


GitHubScraperAgent = GitHubScraper
