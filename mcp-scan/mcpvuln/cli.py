"""Command line interface.

    mcpvuln ./path/to/repo                 # offline scan, no API key needed
    mcpvuln https://github.com/org/repo    # ingest from GitHub
    mcpvuln ./repo --narrative             # add model-written analysis
    mcpvuln ./repo --json out.json         # emit the scan contract
    mcpvuln ./repo --min-confidence 0.7    # tighten the detection threshold
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import List, Optional

from . import __version__
from . import contract as contract_mod
from .patterns import PATTERNS, validate as validate_patterns
from .pipeline import SecurityAnalysisPipeline


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcpvuln",
        description="Vulnerability detection for Model Context Protocol codebases.",
        epilog="Detection is deterministic and needs no API key. "
               "--narrative and --threat-intel are the only network features.",
    )
    p.add_argument("target", nargs="*",
                   help="Local directory or GitHub repository URL. Repeatable.")
    p.add_argument("--out", "-o", default=".",
                   help="Directory for generated reports (default: current directory).")
    p.add_argument("--json", dest="json_path", default=None,
                   help="Also write the scan contract as JSON to this path. "
                        "With multiple targets it is used as a directory.")
    p.add_argument("--min-confidence", type=float, default=None,
                   help="Drop findings below this detector confidence (0.0-1.0).")
    p.add_argument("--narrative", action="store_true",
                   help="Add a model-written analyst narrative. Requires GOOGLE_API_KEY.")
    p.add_argument("--threat-intel", action="store_true",
                   help="Fetch external advisories. Requires FIRECRAWL_API_KEY.")
    p.add_argument("--model", default="models/gemini-2.5-pro",
                   help="Model for --narrative.")
    p.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"],
                   default="none",
                   help="Exit non-zero if any finding reaches this severity. For CI.")
    p.add_argument("--quiet", "-q", action="store_true", help="Only print result paths.")
    p.add_argument("--self-check", action="store_true",
                   help="Validate the pattern set and exit.")
    p.add_argument("--version", action="version", version=f"mcpvuln {__version__}")
    return p


_SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _worst_severity(contract: dict) -> str:
    worst = "none"
    for f in contract.get("findings", []):
        if f.get("informational"):
            continue
        s = str(f.get("cvss_severity", "None")).lower()
        if _SEVERITY_RANK.get(s, 0) > _SEVERITY_RANK[worst]:
            worst = s
    return worst


def _slug(label: str) -> str:
    base = label.rstrip("/\\").replace("\\", "/").split("/")[-1]
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in base) or "scan"


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    if args.self_check:
        problems = validate_patterns()
        if problems:
            print(f"Pattern set INVALID, {len(problems)} problem(s):")
            for p in problems:
                print(f"  - {p}")
            return 1
        print(f"Pattern set OK: {len(PATTERNS)} rules, all compile, no duplicate ids.")
        return 0

    if not args.target:
        build_parser().print_help()
        return 2

    if args.narrative and not os.environ.get("GOOGLE_API_KEY"):
        print("[warning] --narrative requested but GOOGLE_API_KEY is not set. "
              "The deterministic report will still be written.", file=sys.stderr)
    if args.threat_intel and not os.environ.get("FIRECRAWL_API_KEY"):
        print("[warning] --threat-intel requested but FIRECRAWL_API_KEY is not set. "
              "Continuing without it.", file=sys.stderr)

    os.makedirs(args.out, exist_ok=True)
    pipeline = SecurityAnalysisPipeline(
        min_confidence=args.min_confidence,
        narrative=args.narrative,
        threat_intel=args.threat_intel,
        model_name=args.model,
    )

    exit_code = 0
    for target in args.target:
        try:
            contract = pipeline.run(target)
        except Exception as exc:
            print(f"[error] {target}: {exc}", file=sys.stderr)
            exit_code = max(exit_code, 1)
            continue

        slug = _slug(contract["repository"])
        md_path = os.path.join(args.out, f"{slug}_security_report.md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(pipeline.report(contract))

        if args.json_path:
            jp = (os.path.join(args.json_path, f"{slug}.json")
                  if len(args.target) > 1 or os.path.isdir(args.json_path)
                  else args.json_path)
            os.makedirs(os.path.dirname(os.path.abspath(jp)), exist_ok=True)
            contract_mod.save(contract, jp)
            print(f"contract: {jp}")

        scan = contract["scan"]
        print(f"report:   {md_path}")
        if not args.quiet:
            print(f"          {scan['findings_reportable']} reportable, "
                  f"{scan['findings_informational']} informational, "
                  f"across {scan['files_scanned']} files "
                  f"({scan['lines_scanned']:,} lines)")

        if args.fail_on != "none":
            worst = _worst_severity(contract)
            if _SEVERITY_RANK[worst] >= _SEVERITY_RANK[args.fail_on]:
                print(f"[fail-on] worst severity {worst} >= {args.fail_on}", file=sys.stderr)
                exit_code = max(exit_code, 3)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
