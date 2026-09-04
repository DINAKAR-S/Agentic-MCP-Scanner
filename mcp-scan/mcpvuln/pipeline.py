"""The scan pipeline.

Four stages, run in order, each of which can be skipped:

1. **ingest**  - obtain source, from a local path or a GitHub URL
2. **detect**  - deterministic pattern matching (no network, no API key)
3. **score**   - deterministic CVSS v4.0 and SSVC, emitted as a scan contract
4. **report**  - Markdown, plus an optional model-written narrative

This is a staged pipeline and the code says so. An earlier version presented these
stages as a coordinating multi-agent team, but the coordinating model was
constructed and never invoked: every stage was called directly as a Python method.
Naming it accurately costs nothing and makes the architecture reviewable.
"""

from __future__ import annotations

import io
import logging
import os
from typing import Dict, List, Optional, Tuple

from . import contract as contract_mod
from .report_generator import DeterministicReporter, NarrativeReporter
from .vuln_analyzer import SCANNABLE, SKIP_DIRS, VulnerabilityAnalyzer

log = logging.getLogger("mcpvuln")


class SecurityAnalysisPipeline:
    def __init__(self, *, min_confidence: Optional[float] = None,
                 narrative: bool = False, threat_intel: bool = False,
                 model_name: str = "models/gemini-2.5-pro"):
        kwargs = {} if min_confidence is None else {"min_confidence": min_confidence}
        self.analyzer = VulnerabilityAnalyzer(**kwargs)
        self.narrative = narrative
        self.threat_intel = threat_intel
        self.model_name = model_name

    # ------------------------------------------------------------------ ingest

    @staticmethod
    def _read_local(root: str) -> Tuple[Dict[str, str], int]:
        files: Dict[str, str] = {}
        lines = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() not in SCANNABLE:
                    continue
                full = os.path.join(dirpath, fn)
                try:
                    content = io.open(full, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                rel = os.path.relpath(full, root).replace("\\", "/")
                files[rel] = content
                lines += content.count("\n") + 1
        return files, lines

    def ingest(self, target: str) -> Tuple[str, Dict[str, str], int]:
        """Return (label, {path: content}, total_lines)."""
        if os.path.isdir(target):
            files, lines = self._read_local(target)
            # Label with the path as given, not the absolute path: a report is
            # often shared, and an absolute path leaks the author's filesystem.
            label = os.path.normpath(target).replace("\\", "/")
            if label in (".", ""):
                label = os.path.basename(os.path.abspath(target)) or "."
            return label, files, lines

        from .github_scraper import GitHubScraper          # lazy: needs gitingest
        repos = GitHubScraper().scrape_github_repos([target])
        if not repos:
            raise RuntimeError(f"could not ingest {target}")
        files = repos[0]["files"]
        lines = sum(c.count("\n") + 1 for c in files.values())
        return target, files, lines

    # ------------------------------------------------------------------ run

    def run(self, target: str) -> dict:
        label, files, lines = self.ingest(target)
        log.info("ingested %d files, %d lines from %s", len(files), lines, label)

        findings = [f.to_dict() for f in self.analyzer.analyze_files(files)]
        log.info("detection produced %d findings", len(findings))

        intel: List[dict] = []
        if self.threat_intel:
            try:
                from .firecrawl_integration import ThreatIntelClient
                intel = ThreatIntelClient().fetch()
                log.info("threat intelligence: %d entries", len(intel))
            except Exception as exc:                        # never fail the scan
                log.warning("threat intelligence skipped: %s", exc)

        return contract_mod.build(
            label, findings,
            files_scanned=len(files), lines_scanned=lines,
            external_intel=intel,
            config={
                "min_confidence": self.analyzer.min_confidence,
                "narrative": self.narrative,
                "threat_intel": self.threat_intel,
            },
        )

    def report(self, contract: dict) -> str:
        md = DeterministicReporter().render(contract)
        if self.narrative:
            md += NarrativeReporter(self.model_name).render(contract)
        return md


# Backwards-compatible alias for the previous class name.
SecurityAnalysisTeam = SecurityAnalysisPipeline
