"""The published precision, recall and F1 must stay true.

demo/ground-truth.json plus demo/vulnerable and demo/safe make these numbers
reproducible by anyone. They are quoted in the README and in the accompanying
paper, so a change that moves them should fail here first.
"""

import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
MCP_SCAN = os.path.dirname(HERE)
ROOT = os.path.dirname(MCP_SCAN)
SCORER = os.path.join(MCP_SCAN, "benchmark", "score_demo.py")
GT = os.path.join(ROOT, "demo", "ground-truth.json")

pytestmark = pytest.mark.skipif(not os.path.isfile(GT), reason="demo fixtures not present")


@pytest.fixture(scope="module")
def scores(tmp_path_factory):
    out = tmp_path_factory.mktemp("score") / "r.json"
    subprocess.run([sys.executable, SCORER, "--json", str(out)],
                   cwd=MCP_SCAN, check=True, capture_output=True)
    with open(out, encoding="utf-8") as fh:
        return json.load(fh)


def test_no_false_positives(scores):
    """The fixed half must contribute nothing, and nothing on the broken half
    may be unaccounted for."""
    assert scores["totals"]["fp"] == 0


def test_precision_is_one(scores):
    assert scores["totals"]["precision"] == 1.0


def test_recall_matches_the_published_figure(scores):
    assert scores["totals"]["recall"] == pytest.approx(0.864, abs=0.005)


def test_f1_matches_the_published_figure(scores):
    assert scores["totals"]["f1"] == pytest.approx(0.927, abs=0.005)


def test_ground_truth_size(scores):
    assert scores["ground_truth_instances"] == 22


def test_all_four_layers_are_represented(scores):
    assert set(scores["by_layer"]) == {"LLM", "Agentic AI", "MCP", "Traditional Web"}


def test_the_undetected_cases_are_the_protocol_state_ones(scores):
    """The three misses are the cases the design notes predict: properties of
    protocol state rather than lexical features of a line. If a different set
    starts failing, the explanation in the write-up no longer holds."""
    assert set(scores["not_detected"]) == {"D09", "D13", "D16"}


def test_ground_truth_entries_are_wellformed():
    with open(GT, encoding="utf-8") as fh:
        instances = json.load(fh)["instances"]
    ids = [i["id"] for i in instances]
    assert len(ids) == len(set(ids)), "duplicate ground-truth ids"
    for i in instances:
        assert set(i) >= {"id", "file", "lines", "category", "layer", "what"}
        lo, hi = i["lines"]
        assert 0 < lo <= hi, f"{i['id']}: bad line range"
        assert os.path.isfile(os.path.join(ROOT, "demo", "vulnerable", i["file"]))
