#!/usr/bin/env python3
"""Compute precision, recall and F1 against the demo ground truth.

    python benchmark/score_demo.py

demo/vulnerable carries a documented set of planted vulnerabilities, listed in
demo/ground-truth.json. demo/safe is the same code with all of them fixed, so it
contributes only true negatives. Because both halves and the ground truth are
public, every number this prints can be reproduced by anyone.

Unit of evaluation: one (file or function, category) triple, resolved here at
instance granularity because several fixtures plant more than one instance of the
same category in the same file. A finding matches a ground-truth instance when the
file matches, the category matches, and the reported line falls inside that
instance's line range, with a small tolerance since a rule may anchor to the head
of a construct. Multiple findings matching the same instance count once, so a tool
reporting the same issue repeatedly gains no advantage. Findings matching nothing
are de-duplicated by (file, category, line) and counted as false positives.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))

from mcpvuln.vuln_analyzer import VulnerabilityAnalyzer  # noqa: E402

DEMO = os.path.join(ROOT, "demo")
TOLERANCE = 2


def load_ground_truth():
    with open(os.path.join(DEMO, "ground-truth.json"), encoding="utf-8") as fh:
        return json.load(fh)["instances"]


def distance(finding, gt):
    """How far a finding sits from a ground-truth instance, or None if it cannot match.

    Distance rather than a boolean, because two instances of the same category can
    sit a few lines apart in one file. Taking the first match within a tolerance
    window let a finding claim its neighbour and understated recall.
    """
    if finding.file.replace("\\", "/") != gt["file"]:
        return None
    if finding.category != gt["category"]:
        return None
    lo, hi = gt["lines"]
    if lo <= finding.line <= hi:
        return 0
    d = lo - finding.line if finding.line < lo else finding.line - hi
    return d if d <= TOLERANCE else None


def best_match(finding, gts, taken):
    """The nearest unclaimed instance this finding can match."""
    scored = [(d, g) for g in gts
              if (d := distance(finding, g)) is not None and g["id"] not in taken]
    if not scored:
        # already claimed by an earlier finding: still a true positive, not a new one
        scored = [(d, g) for g in gts if (d := distance(finding, g)) is not None]
    if not scored:
        return None
    scored.sort(key=lambda t: t[0])
    return scored[0][1]


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", dest="json_path", help="write results as JSON")
    ap.add_argument("--all", action="store_true",
                    help="include informational findings, not just reportable ones")
    args = ap.parse_args()

    gts = load_ground_truth()
    analyzer = VulnerabilityAnalyzer()

    vuln = analyzer.analyze_path(os.path.join(DEMO, "vulnerable"))
    safe = analyzer.analyze_path(os.path.join(DEMO, "safe"))
    if not args.all:
        vuln = [f for f in vuln if not f.informational]
        safe = [f for f in safe if not f.informational]

    # Match findings to ground-truth instances. One instance can absorb several
    # findings (they count once); findings matching nothing become false positives.
    matched_gt, fp_seen, fps = {}, set(), []
    for f in vuln:
        hit = best_match(f, gts, set(matched_gt))
        if hit:
            matched_gt.setdefault(hit["id"], (f, hit))
        else:
            key = (f.file.replace("\\", "/"), f.category, f.line)
            if key not in fp_seen:
                fp_seen.add(key)
                fps.append(f)
    # anything reported on the fixed half is a false positive by construction
    for f in safe:
        key = (f.file.replace("\\", "/"), f.category, f.line)
        if key not in fp_seen:
            fp_seen.add(key)
            fps.append(f)
    tps = list(matched_gt.values())
    fns = [g for g in gts if g["id"] not in matched_gt]
    vuln_u, safe_u = vuln, safe

    tp, fp, fn = len(tps), len(fps), len(fns)
    p, r, f1 = prf(tp, fp, fn)

    print("=" * 68)
    print("DEMO BENCHMARK: precision, recall and F1 against a public ground truth")
    print("=" * 68)
    print(f"ground-truth instances : {len(gts)}")
    print(f"units reported on demo/vulnerable : {len(vuln_u)}")
    print(f"units reported on demo/safe       : {len(safe_u)}   (every one is a false positive)")
    print()
    print(f"  TP {tp:3d}    FP {fp:3d}    FN {fn:3d}")
    print(f"  Precision {p:.3f}    Recall {r:.3f}    F1 {f1:.3f}")

    print("\nby taxonomy layer:")
    print(f"  {'layer':16s} {'n':>3s} {'TP':>3s} {'FP':>3s} {'FN':>3s} "
          f"{'P':>6s} {'R':>6s} {'F1':>6s}")
    per_layer = {}
    for g in gts:
        per_layer.setdefault(g["layer"], {"n": 0, "tp": 0, "fn": 0, "fp": 0})
        per_layer[g["layer"]]["n"] += 1
    for _f, g in tps:
        per_layer[g["layer"]]["tp"] += 1
    for g in fns:
        per_layer[g["layer"]]["fn"] += 1
    for f in fps:
        per_layer.setdefault(f.layer, {"n": 0, "tp": 0, "fn": 0, "fp": 0})
        per_layer[f.layer]["fp"] += 1
    layer_rows = {}
    for layer, c in sorted(per_layer.items()):
        lp, lr, lf = prf(c["tp"], c["fp"], c["fn"])
        print(f"  {layer:16s} {c['n']:3d} {c['tp']:3d} {c['fp']:3d} {c['fn']:3d} "
              f"{lp:6.3f} {lr:6.3f} {lf:6.3f}")
        layer_rows[layer] = {**c, "precision": round(lp, 3),
                             "recall": round(lr, 3), "f1": round(lf, 3)}

    if fns:
        print("\nnot detected:")
        for g in fns:
            print(f"  {g['id']}  {g['file']}:{g['lines'][0]:<4} {g['category']:28s} {g['what']}")
    if fps:
        print("\nfalse positives:")
        for f in fps:
            print(f"  {f.file}:{f.line:<4} {f.category}")

    results = {
        "ground_truth_instances": len(gts),
        "totals": {"tp": tp, "fp": fp, "fn": fn,
                   "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3)},
        "by_layer": layer_rows,
        "not_detected": [g["id"] for g in fns],
    }
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"\nwrote {args.json_path}")

    print("\nNote: these fixtures carry one clean instance of each class, so detection "
          "here is\neasier than on production code. Treat this as evidence that the rules "
          "fire and\ndiscriminate, not as an estimate of recall on code the tool has not seen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
