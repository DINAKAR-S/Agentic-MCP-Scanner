"""The scan contract: the versioned JSON document the pipeline hands between stages.

The detection stage produces one of these. The reporting stage consumes it. It is
the only thing that crosses the boundary, so a run can be replayed, diffed, or
scored offline without re-running detection, and the reporting model receives
structured input rather than an ad-hoc string.
"""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Iterable
from typing import Any, Dict, List, Optional

from . import __version__
from .scoring import score_finding

SCHEMA_VERSION = "1.0"


def build(repository: str, findings: Iterable[dict], *,
          files_scanned: int = 0, lines_scanned: int = 0,
          external_intel: Optional[List[dict]] = None,
          config: Optional[Dict[str, Any]] = None) -> dict:
    """Assemble a scan contract from raw findings.

    Findings are scored here, so the contract always carries deterministic CVSS
    v4.0 vectors and SSVC priorities. Sorted most severe first.
    """
    scored = [score_finding(f) for f in findings]
    scored.sort(key=lambda f: (-f["risk_index"], -f["confidence"], f["file"], f["line"]))

    reportable = [f for f in scored if not f.get("informational")]
    by_layer: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    for f in scored:
        by_layer[f["layer"]] = by_layer.get(f["layer"], 0) + 1
        by_category[f["category"]] = by_category.get(f["category"], 0) + 1
        by_severity[f["cvss_severity"]] = by_severity.get(f["cvss_severity"], 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "mcpvuln", "version": __version__},
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "repository": repository,
        "config": config or {},
        "scan": {
            "files_scanned": files_scanned,
            "lines_scanned": lines_scanned,
            "findings_total": len(scored),
            "findings_reportable": len(reportable),
            "findings_informational": len(scored) - len(reportable),
            "by_layer": by_layer,
            "by_category": by_category,
            "by_severity": by_severity,
        },
        "findings": scored,
        "external_intel": external_intel or [],
    }


def dumps(contract: dict, indent: int = 2) -> str:
    return json.dumps(contract, indent=indent, ensure_ascii=False)


def save(contract: dict, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dumps(contract))
    return path


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def validate(contract: dict) -> List[str]:
    """Structural check. Empty list means valid."""
    problems: List[str] = []
    for key in ("schema_version", "tool", "repository", "scan", "findings"):
        if key not in contract:
            problems.append(f"missing top-level key: {key}")
    if contract.get("schema_version") != SCHEMA_VERSION:
        problems.append(
            f"schema_version {contract.get('schema_version')!r} "
            f"!= expected {SCHEMA_VERSION!r}"
        )
    for i, f in enumerate(contract.get("findings", [])):
        for key in ("pattern_id", "category", "layer", "file", "line",
                    "confidence", "cvss_vector", "cvss_base_score", "ssvc"):
            if key not in f:
                problems.append(f"finding[{i}] missing key: {key}")
    return problems
