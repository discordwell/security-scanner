from __future__ import annotations

from ..models import Observation, ObservationSeverity, ToolExecution, ToolStatus
from .types import AdapterResult


class AngrAdapter:
    def analyze(self, suspicious_functions: int, enabled: bool) -> AdapterResult:
        if not enabled or suspicious_functions == 0:
            return AdapterResult(
                tool_run=ToolExecution(
                    tool="angr",
                    status=ToolStatus.UNAVAILABLE,
                    summary="Targeted symbolic execution skipped.",
                    details={"enabled": enabled, "suspicious_functions": suspicious_functions},
                )
            )
        observation = Observation(
            source="angr-placeholder",
            category="symbolic_execution",
            severity=ObservationSeverity.INFO,
            message="Suspicious regions were queued for targeted symbolic execution, but no external angr runner is configured in local mode.",
            evidence={"suspicious_functions": suspicious_functions},
            tags=["symbolic"],
        )
        return AdapterResult(
            observations=[observation],
            tool_run=ToolExecution(
                tool="angr",
                status=ToolStatus.UNAVAILABLE,
                summary="Targeted symbolic execution was requested but no backend is configured.",
                details={"queued_regions": suspicious_functions},
            ),
        )
