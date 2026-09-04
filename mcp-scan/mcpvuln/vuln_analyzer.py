"""Detection layer.

Scans source text with the rules in :mod:`mcpvuln.patterns` and emits scored,
de-duplicated findings.

Three things this does that a naive line-by-line matcher does not:

* **Whole-file matching.** Patterns may span lines. Offsets are mapped back to
  line numbers afterwards.
* **Comment and string suppression.** A ``code_only`` pattern that matches inside
  a comment, docstring or Markdown prose is discarded. Most of the false positives
  measured against the official MCP SDK were documentation text.
* **Suppression.** ``# mcpvuln: ignore-file``, ``# mcpvuln: ignore`` and
  ``# mcpvuln: ignore[rule.id]`` let a codebase silence a known false positive
  without abandoning the scanner.
* **Confidence.** Every finding carries a score derived from the pattern's prior
  and the context it was found in. Downstream stages rank and filter on it, which
  is what lets the reporting model see candidates in a useful order.
"""

from __future__ import annotations

import io
import os
import re
import tokenize
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

from .patterns import PATTERNS, Pattern

# Extensions we treat as executable source. Everything else is prose or config,
# where a ``code_only`` pattern means nothing.
CODE_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb",
            ".php", ".cs", ".sh", ".bash", ".c", ".cc", ".cpp", ".h"}
CONFIG_EXT = {".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".cfg"}
PROSE_EXT = {".md", ".rst", ".txt", ".adoc"}
SCANNABLE = CODE_EXT | CONFIG_EXT | PROSE_EXT

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
             "build", ".mypy_cache", ".pytest_cache", ".tox", "vendor",
             "site-packages", ".next", "target"}

# Paths that are documentation or translation rather than shipped behaviour.
DOC_DIR_RE = re.compile(r"(?:^|[\\/])(?:docs?|i18n|locales?|translations?|examples?|"
                        r"samples?|website|\.github)(?:[\\/]|$)", re.IGNORECASE)
TEST_PATH_RE = re.compile(r"(?:^|[\\/])(?:tests?|__tests__|spec|fixtures?)(?:[\\/]|$)|"
                          r"(?:^|[\\/])(?:test_[^\\/]*|[^\\/]*_test)\.[a-z]+$", re.IGNORECASE)

# Context multipliers applied to a pattern's prior confidence.
W_DOC_PATH = 0.25
W_TEST_PATH = 0.45
W_PROSE_FILE = 0.20
W_CONFIG_FILE = 0.85

# Findings below this are dropped entirely. Between this and REPORT_THRESHOLD
# they are kept but marked informational.
MIN_CONFIDENCE = 0.15
REPORT_THRESHOLD = 0.50


@dataclass
class Finding:
    pattern_id: str
    category: str
    layer: str
    file: str
    line: int
    end_line: int
    code: str
    description: str
    remediation: str
    confidence: float
    cvss_metrics: Dict[str, str]
    in_comment: bool = False
    informational: bool = False

    def key(self) -> Tuple[str, str, int]:
        """De-duplication key: the unit of evaluation is (file, category, line)."""
        return (self.file, self.category, self.line)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- context


def _python_masked_spans(source: str) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """Return (comment_spans, string_spans) as character offsets in Python source."""
    comments: List[Tuple[int, int]] = []
    strings: List[Tuple[int, int]] = []
    # Offset of the first character of each 1-indexed line.
    starts = [0]
    for line in source.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))

    def off(row: int, col: int) -> int:
        return starts[row - 1] + col if 0 < row <= len(starts) else 0

    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                comments.append((off(tok.start[0], tok.start[1]), off(tok.end[0], tok.end[1])))
            elif tok.type == tokenize.STRING:
                strings.append((off(tok.start[0], tok.start[1]), off(tok.end[0], tok.end[1])))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        # Unparseable file. Fall back to the line heuristic.
        return _heuristic_masked_spans(source)
    return comments, strings


_LINE_COMMENT_RE = re.compile(r"^\s*(?:#|//|--|\*|/\*|<!--)")

# Suppression directives. Any scanner needs a way to say "I know, this is fine",
# otherwise the only way to silence a false positive is to stop running the tool.
#   # mcpvuln: ignore-file            -> skip the whole file
#   # mcpvuln: ignore                 -> skip this line (or the line above)
#   # mcpvuln: ignore[rule.id,other]  -> skip only those rules on this line
_IGNORE_FILE_RE = re.compile(r"mcpvuln:[ 	]*ignore-file")
_IGNORE_LINE_RE = re.compile(r"mcpvuln:[ 	]*ignore(?:\[([^\]]*)\])?(?!-)")


def _suppressions(source: str):
    """Return (whole_file_suppressed, {line_number: set_of_rule_ids_or_ALL})."""
    if _IGNORE_FILE_RE.search(source[:4000]):
        return True, {}
    per_line = {}
    for i, line in enumerate(source.splitlines(), 1):
        m = _IGNORE_LINE_RE.search(line)
        if not m:
            continue
        rules = ({r.strip() for r in m.group(1).split(",") if r.strip()}
                 if m.group(1) else {"*"})
        # A directive applies to its own line, and to the next line when it sits
        # on a line of its own, which is how people usually write them.
        per_line.setdefault(i, set()).update(rules)
        if line.strip().startswith(("#", "//", "--")):
            per_line.setdefault(i + 1, set()).update(rules)
    return False, per_line


def _suppressed(per_line, line_no: int, rule_id: str) -> bool:
    rules = per_line.get(line_no)
    if not rules:
        return False
    return "*" in rules or rule_id in rules


def _heuristic_masked_spans(source: str) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """(comment_spans, string_spans) for non-Python source. Strings are not tracked."""
    comments: List[Tuple[int, int]] = []
    pos = 0
    for line in source.splitlines(keepends=True):
        if _LINE_COMMENT_RE.match(line):
            comments.append((pos, pos + len(line)))
        pos += len(line)
    return comments, []


def _in_span(offset: int, spans: Sequence[Tuple[int, int]]) -> bool:
    return any(a <= offset < b for a, b in spans)


def _line_of(offset: int, line_starts: Sequence[int]) -> int:
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def context_weight(file_path: str) -> float:
    """How much to trust any finding in this file, before the pattern's own prior."""
    ext = os.path.splitext(file_path)[1].lower()
    w = 1.0
    if ext in PROSE_EXT:
        w *= W_PROSE_FILE
    elif ext in CONFIG_EXT:
        w *= W_CONFIG_FILE
    if DOC_DIR_RE.search(file_path):
        w *= W_DOC_PATH
    if TEST_PATH_RE.search(file_path):
        w *= W_TEST_PATH
    return w


# --------------------------------------------------------------------------- analyzer


class VulnerabilityAnalyzer:
    """Deterministic detection. No model calls, no network, no API key."""

    def __init__(self, patterns: Optional[Sequence[Pattern]] = None,
                 min_confidence: float = MIN_CONFIDENCE):
        self.patterns = list(patterns if patterns is not None else PATTERNS)
        self.min_confidence = min_confidence
        self._compiled = [(p, p.compiled()) for p in self.patterns]

    def analyze(self, code_content: str, file_path: str) -> List[Finding]:
        if not code_content:
            return []

        file_suppressed, per_line = _suppressions(code_content)
        if file_suppressed:
            return []

        ext = os.path.splitext(file_path)[1].lower()
        is_code = ext in CODE_EXT
        comment_spans, string_spans = (
            _python_masked_spans(code_content) if ext == ".py"
            else _heuristic_masked_spans(code_content))

        line_starts = [0]
        for line in code_content.splitlines(keepends=True):
            line_starts.append(line_starts[-1] + len(line))
        lines = code_content.splitlines()

        base_weight = context_weight(file_path)
        found: Dict[Tuple[str, str, int], Finding] = {}

        for pattern, rx in self._compiled:
            for m in rx.finditer(code_content):
                start = m.start()
                in_comment = _in_span(start, comment_spans)
                in_string = _in_span(start, string_spans)

                # A code-only pattern inside a comment is noise.
                if pattern.code_only and in_comment:
                    continue
                # ...and inside a string literal too, unless the rule's evidence
                # legitimately lives in one (a shell command, SQL, a path, a URL).
                if pattern.code_only and in_string and not pattern.allow_in_string:
                    continue
                # A code-only pattern in a prose file is noise by definition.
                if pattern.code_only and not is_code and ext in PROSE_EXT:
                    continue

                conf = pattern.confidence * base_weight
                if in_comment:
                    conf *= 0.3
                if conf < self.min_confidence:
                    continue

                ln = _line_of(start, line_starts)
                if _suppressed(per_line, ln, pattern.id):
                    continue
                end_ln = _line_of(max(m.end() - 1, start), line_starts)
                snippet = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""

                f = Finding(
                    pattern_id=pattern.id,
                    category=pattern.category,
                    layer=pattern.layer,
                    file=file_path,
                    line=ln,
                    end_line=end_ln,
                    code=snippet[:300],
                    description=pattern.description,
                    remediation=pattern.remediation,
                    confidence=round(min(conf, 1.0), 3),
                    cvss_metrics=dict(pattern.cvss),
                    in_comment=in_comment,
                    informational=conf < REPORT_THRESHOLD,
                )
                # De-duplicate on (file, category, line); keep the most confident.
                prev = found.get(f.key())
                if prev is None or f.confidence > prev.confidence:
                    found[f.key()] = f

        return sorted(found.values(), key=lambda x: (-x.confidence, x.file, x.line))

    # ------------------------------------------------------------------ directories

    def analyze_path(self, root: str) -> List[Finding]:
        """Walk a directory and analyze every scannable file."""
        out: List[Finding] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() not in SCANNABLE:
                    continue
                full = os.path.join(dirpath, fn)
                try:
                    content = open(full, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                rel = os.path.relpath(full, root).replace("\\", "/")
                out.extend(self.analyze(content, rel))
        return sorted(out, key=lambda x: (-x.confidence, x.file, x.line))

    def analyze_files(self, files: Dict[str, str]) -> List[Finding]:
        """Analyze an in-memory {path: content} mapping, as returned by the scraper."""
        out: List[Finding] = []
        for path, content in files.items():
            out.extend(self.analyze(content, path))
        return sorted(out, key=lambda x: (-x.confidence, x.file, x.line))


# Backwards-compatible alias. The old class name subclassed an agno Agent whose
# model was constructed but never invoked; the detection layer has never needed one.
VulnerabilityAnalysisAgent = VulnerabilityAnalyzer
