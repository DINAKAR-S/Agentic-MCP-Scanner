"""mcpvuln: vulnerability detection for Model Context Protocol codebases.

The detection layer is deterministic and has no network or API-key dependency, so
``VulnerabilityAnalyzer`` and the scoring and contract modules import cleanly on
their own. The reporting and threat-intelligence stages pull in heavier optional
dependencies and are imported lazily, on first use.
"""

__version__ = "0.3.0"
__author__ = "Dinakar S"
__description__ = "MCP vulnerability detection with a reproducible benchmark"

__all__ = [
    "VulnerabilityAnalyzer",
    "Finding",
    "PATTERNS",
    "contract",
    "scoring",
    "SecurityAnalysisPipeline",
]


def __getattr__(name):
    # Lazy so that `import mcpvuln` never requires the reporting dependencies.
    if name in ("VulnerabilityAnalyzer", "Finding"):
        from . import vuln_analyzer
        return getattr(vuln_analyzer, name)
    if name == "PATTERNS":
        from .patterns import PATTERNS
        return PATTERNS
    if name in ("contract", "scoring"):
        import importlib
        return importlib.import_module(f".{name}", __name__)
    if name == "SecurityAnalysisPipeline":
        from .pipeline import SecurityAnalysisPipeline
        return SecurityAnalysisPipeline
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
