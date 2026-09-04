#!/usr/bin/env python3
"""Enforce the false-positive budget in CI.

The benign corpus is clean by construction, so every finding against it is a
candidate false positive. v0.1.0 scored 1.28 per 100 LOC. Regressing past the
budget means the detector got noisy again.

    python benchmark/check_budget.py results.json [--budget 0.05]
"""

import argparse
import json
import sys

DEFAULT_BUDGET = 0.05


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results", help="JSON written by run_benchmark.py --json")
    ap.add_argument("--budget", type=float, default=DEFAULT_BUDGET,
                    help="maximum findings per 100 LOC on clean code")
    args = ap.parse_args()

    with open(args.results, encoding="utf-8") as fh:
        totals = json.load(fh)["totals"]

    rate = totals["per_100_loc"]
    print("%d findings over %d lines = %s per 100 LOC (budget %s)"
          % (totals["findings"], totals["lines"], rate, args.budget))

    if rate > args.budget:
        print("FAIL: %s exceeds the budget of %s" % (rate, args.budget), file=sys.stderr)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
