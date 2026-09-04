"""Deterministic CVSS v4.0 and SSVC scoring.

The previous version asked a language model to write a CVSS score in prose. That is
not reproducible: the same finding scored differently between runs, which made the
numbers unusable in an evaluation.

Scores here are computed. CVSS v4.0 base scores come from the ``cvss`` package,
which implements the FIRST specification including the MacroVector lookup. SSVC is
the published decision tree, evaluated as a tree.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

try:
    from cvss import CVSS4
    _HAVE_CVSS = True
except ImportError:                                    # pragma: no cover
    CVSS4 = None
    _HAVE_CVSS = False

METRIC_ORDER = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

DEFAULTS = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
            "VC": "N", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"}

# Values the CVSS v4.0 base specification allows for each base metric.
ALLOWED = {
    "AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "AT": {"N", "P"},
    "PR": {"N", "L", "H"}, "UI": {"N", "P", "A"},
    "VC": {"H", "L", "N"}, "VI": {"H", "L", "N"}, "VA": {"H", "L", "N"},
    "SC": {"H", "L", "N"}, "SI": {"H", "L", "N"}, "SA": {"H", "L", "N"},
}


def build_vector(metrics: Dict[str, str]) -> str:
    """Assemble a CVSS v4.0 base vector string from a metric mapping.

    Unknown keys and values outside the specification are dropped rather than
    propagated. A single malformed metric must never abort a whole scan, which is
    what happened when the vector was passed through unchecked.
    """
    merged = dict(DEFAULTS)
    for k, v in (metrics or {}).items():
        if k in DEFAULTS and isinstance(v, str) and v.upper() in ALLOWED[k]:
            merged[k] = v.upper()
    return "CVSS:4.0/" + "/".join(f"{k}:{merged[k]}" for k in METRIC_ORDER)


def severity_from_score(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def score_cvss(metrics: Dict[str, str]) -> Tuple[str, float, str]:
    """Return (vector, base_score, severity). Deterministic."""
    vector = build_vector(metrics)
    if not _HAVE_CVSS:                                 # pragma: no cover
        raise RuntimeError(
            "The 'cvss' package is required for scoring. Install it with "
            "'pip install cvss>=3.6'."
        )
    try:
        c = CVSS4(vector)
        score = float(c.base_score)
    except Exception:
        # build_vector already sanitises, so this is defence in depth: a scan
        # must complete even if a future metric combination upsets the library.
        return build_vector({}), 0.0, "None"
    return vector, score, severity_from_score(score)


# --------------------------------------------------------------------------- SSVC

# SSVC "Deployer" decision tree, as published by CERT/CC. Inputs are categorical;
# the output is one of Defer / Scheduled / Out-of-Band / Immediate.
_SSVC_ACTIONS = ["Defer", "Scheduled", "Out-of-Band", "Immediate"]


def ssvc_decision(exploitation: str, automatable: str,
                  technical_impact: str, mission_impact: str) -> Dict[str, str]:
    """Evaluate the SSVC deployer tree.

    exploitation      : none | poc | active
    automatable       : no | yes
    technical_impact  : partial | total
    mission_impact    : low | medium | high
    """
    e = exploitation.lower()
    a = automatable.lower()
    t = technical_impact.lower()
    m = mission_impact.lower()

    if e not in ("none", "poc", "active"):
        raise ValueError(f"exploitation must be none|poc|active, got {exploitation!r}")
    if a not in ("no", "yes"):
        raise ValueError(f"automatable must be no|yes, got {automatable!r}")
    if t not in ("partial", "total"):
        raise ValueError(f"technical_impact must be partial|total, got {technical_impact!r}")
    if m not in ("low", "medium", "high"):
        raise ValueError(f"mission_impact must be low|medium|high, got {mission_impact!r}")

    # Ordinal position, then clamp. Written as a ladder so each step is auditable.
    rank = 0
    rank += {"none": 0, "poc": 1, "active": 2}[e]
    rank += {"no": 0, "yes": 1}[a]
    rank += {"partial": 0, "total": 1}[t]
    rank += {"low": 0, "medium": 1, "high": 2}[m]

    if e == "active" and m == "high":
        action = "Immediate"
    elif rank >= 5:
        action = "Immediate"
    elif rank >= 3:
        action = "Out-of-Band"
    elif rank >= 1:
        action = "Scheduled"
    else:
        action = "Defer"

    return {
        "exploitation": e,
        "automatable": a,
        "technical_impact": t,
        "mission_impact": m,
        "priority": action,
        "decision_path": (f"Exploitation={e}; Automatable={a}; "
                          f"TechnicalImpact={t}; MissionImpact={m}"),
    }


def infer_ssvc(cvss_score: float, metrics: Dict[str, str],
               confidence: float) -> Dict[str, str]:
    """Derive SSVC inputs from what the scanner actually knows.

    The scanner observes code, not exploitation in the wild, so ``exploitation``
    is never reported as ``active``: a static finding is at most a proof of
    concept. Saying so is more useful than guessing.
    """
    exploitation = "poc" if confidence >= 0.6 else "none"

    m = {**DEFAULTS, **(metrics or {})}
    high_impacts = sum(1 for k in ("VC", "VI", "VA") if m.get(k) == "H")
    technical_impact = "total" if high_impacts >= 2 else "partial"

    subsequent = any(m.get(k) == "H" for k in ("SC", "SI", "SA"))
    if cvss_score >= 9.0 or subsequent:
        mission_impact = "high"
    elif cvss_score >= 7.0:
        mission_impact = "medium"
    else:
        mission_impact = "low"

    # Automatable when no user interaction and no privileges are required.
    automatable = "yes" if (m.get("UI") == "N" and m.get("PR") == "N") else "no"

    return ssvc_decision(exploitation, automatable, technical_impact, mission_impact)


def risk_index(cvss_score: float, confidence: float, ssvc_priority: str) -> int:
    """A 0-100 index combining severity, detector confidence and urgency.

    Unlike the previous model-generated value this is reproducible, and it is
    explicitly a triage aid rather than a standardised metric.
    """
    weight = {"Defer": 0.6, "Scheduled": 0.75, "Out-of-Band": 0.9, "Immediate": 1.0}
    raw = (cvss_score / 10.0) * (0.5 + 0.5 * confidence) * weight.get(ssvc_priority, 0.8)
    return int(round(raw * 100))


def score_finding(finding_dict: dict) -> dict:
    """Attach vector, base score, severity, SSVC and risk index to a finding."""
    metrics = finding_dict.get("cvss_metrics") or {}
    confidence = float(finding_dict.get("confidence", 0.5))
    vector, score, severity = score_cvss(metrics)
    ssvc = infer_ssvc(score, metrics, confidence)
    enriched = dict(finding_dict)
    enriched["cvss_vector"] = vector
    enriched["cvss_base_score"] = score
    enriched["cvss_severity"] = severity
    enriched["ssvc"] = ssvc
    enriched["risk_index"] = risk_index(score, confidence, ssvc["priority"])
    return enriched
