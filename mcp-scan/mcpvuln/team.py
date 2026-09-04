"""Deprecated shim.

``SecurityAnalysisTeam`` is now :class:`mcpvuln.pipeline.SecurityAnalysisPipeline`.
The rename is deliberate: the previous class presented the stages as a coordinating
multi-agent team, but the coordinating model was constructed and never invoked.
"""

import warnings

from .pipeline import SecurityAnalysisPipeline

__all__ = ["SecurityAnalysisTeam", "SecurityAnalysisPipeline"]


class SecurityAnalysisTeam(SecurityAnalysisPipeline):
    def __init__(self, *args, **kwargs):
        warnings.warn(
            "SecurityAnalysisTeam is deprecated; use "
            "mcpvuln.pipeline.SecurityAnalysisPipeline.",
            DeprecationWarning, stacklevel=2,
        )
        super().__init__(*args, **kwargs)
