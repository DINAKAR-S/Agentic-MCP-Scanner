#!/usr/bin/env python3
"""Measure the detector against the benign control corpus.

    python benchmark/run_benchmark.py --fetch          # clone the pinned corpus
    python benchmark/run_benchmark.py                  # measure
    python benchmark/run_benchmark.py --json out.json  # machine-readable

Every finding raised against this corpus is a candidate false positive, because the
corpus is clean by construction. The headline number is findings per 100 lines of
code. The v0.1.0 pattern set scored 1.28; anything above roughly 0.05 means the
detector is still too noisy to be useful on a real repository.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from mcpvuln.vuln_analyzer import SCANNABLE, SKIP_DIRS, VulnerabilityAnalyzer  # noqa: E402

CORPUS = json.load(open(os.path.join(HERE, "corpus.json"), encoding="utf-8"))
CHECKOUTS = os.path.join(HERE, "corpus")


def fetch() -> None:
    os.makedirs(CHECKOUTS, exist_ok=True)
    for repo in CORPUS["repos"]:
        dest = os.path.join(CHECKOUTS, repo["name"])
        if not os.path.isdir(os.path.join(dest, ".git")):
            print("cloning " + repo["url"] + " ...")
            subprocess.run(["git", "clone", "--quiet", repo["url"], dest], check=True)
        print("checking out " + repo["name"] + " @ " + repo["commit"][:7])
        subprocess.run(["git", "-C", dest, "fetch", "--quiet", "origin", repo["commit"]],
                       check=False)
        subprocess.run(["git", "-C", dest, "checkout", "--quiet", repo["commit"]], check=True)


def count_lines(root):
    files = lines = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() not in SCANNABLE:
                continue
            files += 1
            try:
                with open(os.path.join(dirpath, fn), encoding="utf-8", errors="ignore") as fh:
                    lines += fh.read().count("\n") + 1
            except OSError:
                pass
    return files, lines


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch", action="store_true", help="clone/checkout the pinned corpus")
    ap.add_argument("--json", dest="json_path", help="write results as JSON")
    ap.add_argument("--sample", type=int, default=25,
                    help="sample size to print for manual adjudication")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    if args.fetch:
        fetch()

    if not os.path.isdir(CHECKOUTS):
        print("corpus not present. Run with --fetch first.", file=sys.stderr)
        return 2

    analyzer = VulnerabilityAnalyzer()
    results = {"repos": [], "totals": {}}
    all_findings = []
    tot_files = tot_lines = 0

    for repo in CORPUS["repos"]:
        root = os.path.join(CHECKOUTS, repo["name"])
        if not os.path.isdir(root):
            print("missing checkout: " + root, file=sys.stderr)
            return 2
        files, lines = count_lines(root)
        findings = analyzer.analyze_path(root)
        reportable = [f for f in findings if not f.informational]
        all_findings += [(repo["name"], f) for f in findings]
        tot_files += files
        tot_lines += lines
        results["repos"].append({
            "name": repo["name"], "commit": repo["commit"],
            "files": files, "lines": lines,
            "findings": len(findings), "reportable": len(reportable),
            "informational": len(findings) - len(reportable),
            "per_100_loc": round(100.0 * len(findings) / lines, 3) if lines else 0.0,
        })

    base = CORPUS["baseline_v0_1_0"]
    per100 = round(100.0 * len(all_findings) / tot_lines, 3) if tot_lines else 0.0
    reportable_total = sum(r["reportable"] for r in results["repos"])
    results["totals"] = {
        "files": tot_files, "lines": tot_lines,
        "findings": len(all_findings), "reportable": reportable_total,
        "per_100_loc": per100,
        "baseline_per_100_loc": base["per_100_loc"],
        "reduction_factor": (round(base["per_100_loc"] / per100, 1) if per100 else None),
    }

    print("=" * 66)
    print("BENIGN CORPUS: every finding here is a candidate false positive")
    print("=" * 66)
    header = "%-14s %7s %9s %7s %7s %9s" % ("repo", "files", "lines", "find", "report", "/100LOC")
    print(header)
    for r in results["repos"]:
        print("%-14s %7d %9d %7d %7d %9.3f" % (
            r["name"], r["files"], r["lines"], r["findings"],
            r["reportable"], r["per_100_loc"]))
    t = results["totals"]
    print("-" * 66)
    print("%-14s %7d %9d %7d %7d %9.3f" % (
        "TOTAL", t["files"], t["lines"], t["findings"],
        t["reportable"], t["per_100_loc"]))
    print()
    print("v0.1.0 baseline : %s findings per 100 LOC (%d raw)"
          % (base["per_100_loc"], base["raw_findings"]))
    print("current         : %s findings per 100 LOC (%d raw, %d reportable)"
          % (t["per_100_loc"], t["findings"], t["reportable"]))
    if t["reduction_factor"]:
        print("reduction       : %sx fewer findings on clean code" % t["reduction_factor"])

    if all_findings:
        cat = collections.Counter(f.category for _, f in all_findings)
        print("\nby category:")
        for c, n in cat.most_common(15):
            print("  %6d  %s" % (n, c))

        random.seed(args.seed)
        sample = random.sample(all_findings, min(args.sample, len(all_findings)))
        print("\nrandom sample (seed %d, n=%d) for manual adjudication:"
              % (args.seed, len(sample)))
        for i, (repo, f) in enumerate(sample, 1):
            flag = " [informational]" if f.informational else ""
            print("\n%2d. [%s] %s/%s:%d conf=%s rule=%s%s"
                  % (i, f.category, repo, f.file, f.line, f.confidence, f.pattern_id, flag))
            print("     " + f.code[:120])

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print("\nwrote " + args.json_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
