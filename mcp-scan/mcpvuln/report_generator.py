"""Reporting.

Two reporters:

* :class:`DeterministicReporter` renders the scan contract to Markdown with no
  model call at all. It is the default, it needs no API key, and its output is
  byte-identical for identical input. Every CVSS vector and SSVC priority it
  prints was computed, not generated.
* :class:`NarrativeReporter` optionally adds a written analysis on top, using a
  language model. It receives the structured contract rather than a truncated
  string, and it processes **all** reportable findings in batches. The previous
  implementation passed ``findings[:20]``, silently discarding everything else.
"""

from __future__ import annotations

import logging
import os
import textwrap
from typing import List, Optional

log = logging.getLogger("mcpvuln.report")

BATCH_SIZE = 40


# --------------------------------------------------------------------------- markdown


class DeterministicReporter:
    """Contract -> Markdown. No model, no network."""

    def render(self, contract: dict) -> str:
        scan = contract["scan"]
        out: List[str] = []
        a = out.append

        a(f"# Security report: {contract['repository']}\n")
        a(f"Generated {contract['generated_at']} by "
          f"{contract['tool']['name']} {contract['tool']['version']} "
          f"(contract schema {contract['schema_version']}).\n")

        a("## Summary\n")
        a("| | |\n|---|---|")
        a(f"| Files scanned | {scan['files_scanned']} |")
        a(f"| Lines scanned | {scan['lines_scanned']:,} |")
        a(f"| Reportable findings | {scan['findings_reportable']} |")
        a(f"| Informational (below confidence threshold) | {scan['findings_informational']} |")
        a("")

        if scan.get("by_severity"):
            a("### By severity\n")
            a("| Severity | Findings |\n|---|---|")
            for sev in ("Critical", "High", "Medium", "Low", "None"):
                if sev in scan["by_severity"]:
                    a(f"| {sev} | {scan['by_severity'][sev]} |")
            a("")

        if scan.get("by_layer"):
            a("### By taxonomy layer\n")
            a("| Layer | Findings |\n|---|---|")
            for layer, n in sorted(scan["by_layer"].items(), key=lambda kv: -kv[1]):
                a(f"| {layer} | {n} |")
            a("")

        reportable = [f for f in contract["findings"] if not f.get("informational")]
        if not reportable:
            a("No findings above the reporting confidence threshold.\n")
        else:
            a("## Findings\n")
            for i, f in enumerate(reportable, 1):
                a(f"### {i}. {f['category']} in `{f['file']}` line {f['line']}\n")
                a(f"- **Layer:** {f['layer']}")
                a(f"- **CVSS v4.0:** {f['cvss_base_score']} ({f['cvss_severity']})")
                a(f"- **Vector:** `{f['cvss_vector']}`")
                a(f"- **SSVC priority:** {f['ssvc']['priority']}")
                a(f"- **Decision path:** {f['ssvc']['decision_path']}")
                a(f"- **Risk index:** {f['risk_index']}/100")
                a(f"- **Detector confidence:** {f['confidence']}  "
                  f"(rule `{f['pattern_id']}`)")
                a(f"\n{f['description']}\n")
                if f.get("code"):
                    a("```\n" + f["code"] + "\n```")
                if f.get("remediation"):
                    a(f"\n**Remediation.** {f['remediation']}\n")

        informational = [f for f in contract["findings"] if f.get("informational")]
        if informational:
            a("\n## Informational\n")
            a("Below the reporting confidence threshold. Listed for completeness; "
              "each needs manual confirmation.\n")
            a("| File | Line | Category | Confidence |\n|---|---|---|---|")
            for f in informational[:200]:
                a(f"| `{f['file']}` | {f['line']} | {f['category']} | {f['confidence']} |")
            if len(informational) > 200:
                a(f"\n_{len(informational) - 200} further informational findings omitted._")
            a("")

        if contract.get("external_intel"):
            a("\n## External threat intelligence\n")
            for v in contract["external_intel"]:
                a(f"- **{v.get('name', 'Unknown')}** - {v.get('description', '')[:200]}  \n"
                  f"  {v.get('source_url', '')}")
            a("")

        a("\n---\n")
        a(textwrap.dedent("""\
            **How to read this.** CVSS v4.0 vectors and base scores are computed from
            the finding's metrics using the FIRST specification, and SSVC priorities are
            evaluated as a decision tree. Both are reproducible: the same contract always
            produces the same scores. Detector confidence is the scanner's own estimate
            that a finding is real, and is not part of any standard. `Exploitation` is
            never reported as `active`, because static analysis observes code rather than
            exploitation in the wild.
            """))
        return "\n".join(out)


# --------------------------------------------------------------------------- narrative


class NarrativeReporter:
    """Optional model-written analysis layered on the deterministic report."""

    SYSTEM = (
        "You are a security analyst reviewing findings from a static scanner for "
        "Model Context Protocol codebases.\n"
        "The CVSS v4.0 vectors, base scores and SSVC priorities in the input were "
        "computed deterministically. Do not recompute, contradict or restate them.\n"
        "Your job is the part a calculator cannot do: explain how findings chain "
        "together, which are likely false positives given the surrounding code, and "
        "what a team should fix first and why.\n"
        "If a finding looks like a false positive, say so plainly."
    )

    def __init__(self, model_name: str = "models/gemini-2.5-pro",
                 api_key: Optional[str] = None):
        self.model_name = model_name
        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY")
        self._model = None

    def available(self) -> bool:
        return bool(self.api_key)

    def _client(self):
        if self._model is None:
            import google.generativeai as genai  # imported lazily
            genai.configure(api_key=self.api_key)
            self._model = genai.GenerativeModel(self.model_name)
        return self._model

    @staticmethod
    def _compact(f: dict) -> dict:
        return {
            "id": f["pattern_id"], "category": f["category"], "layer": f["layer"],
            "file": f["file"], "line": f["line"], "code": f.get("code", "")[:200],
            "cvss": f["cvss_base_score"], "severity": f["cvss_severity"],
            "ssvc": f["ssvc"]["priority"], "confidence": f["confidence"],
        }

    def render(self, contract: dict) -> str:
        if not self.available():
            return ("\n## Analyst narrative\n\n"
                    "_Skipped: GOOGLE_API_KEY is not set. The deterministic report above "
                    "is complete on its own._\n")

        import json
        reportable = [f for f in contract["findings"] if not f.get("informational")]
        if not reportable:
            return "\n## Analyst narrative\n\nNo reportable findings to analyse.\n"

        try:
            model = self._client()
        except Exception as exc:
            log.warning("narrative unavailable: %s", exc)
            return ("\n## Analyst narrative\n\n_Unavailable: could not initialise the "
                    "model (%s). The deterministic report above is complete on its "
                    "own._\n" % type(exc).__name__)

        # Every reportable finding is processed, in batches. Nothing is truncated away.
        sections: List[str] = []
        failed = 0
        total_batches = (len(reportable) + BATCH_SIZE - 1) // BATCH_SIZE
        for i in range(0, len(reportable), BATCH_SIZE):
            batch = reportable[i:i + BATCH_SIZE]
            payload = {
                "repository": contract["repository"],
                "batch": i // BATCH_SIZE + 1,
                "of_batches": total_batches,
                "summary": contract["scan"],
                "findings": [self._compact(f) for f in batch],
            }
            try:
                resp = model.generate_content(
                    self.SYSTEM + "\n\n" + json.dumps(payload, ensure_ascii=False)
                )
                sections.append(getattr(resp, "text", "") or "")
            except Exception as exc:
                # Detection already succeeded. An optional commentary stage must
                # never discard completed work because a remote service is down,
                # rate-limiting, or holding a stale key.
                failed += 1
                log.warning("narrative batch %d/%d failed: %s",
                            i // BATCH_SIZE + 1, total_batches, exc)

        out = "\n## Analyst narrative\n\n"
        if failed:
            out += ("_%d of %d batches could not be generated and are omitted. "
                    "The deterministic report above is unaffected._\n\n"
                    % (failed, total_batches))
        body = "\n\n".join(s.strip() for s in sections if s.strip())
        return out + (body + "\n" if body else "_No narrative was produced._\n")


# Backwards-compatible alias.
ReportGeneratorAgent = DeterministicReporter
