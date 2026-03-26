from __future__ import annotations

import logging

from ..models import Observation, ObservationSeverity, ToolExecution, ToolStatus
from .types import AdapterResult

logger = logging.getLogger(__name__)


CAPABILITIES: list[tuple[tuple[str, ...], str, ObservationSeverity, str]] = [
    (("CreateRemoteThread", "WriteProcessMemory"), "process_injection", ObservationSeverity.HIGH, "Likely process injection capability."),
    (("VirtualAlloc", "WriteProcessMemory"), "memory_exec", ObservationSeverity.HIGH, "Likely executable memory staging."),
    (("https://", "WriteProcessMemory"), "downloader", ObservationSeverity.HIGH, "Likely network staging or download capability."),
    (("powershell", "cmd.exe"), "script_execution", ObservationSeverity.MEDIUM, "Likely shell or script execution capability."),
    (("ptrace",), "anti_analysis", ObservationSeverity.MEDIUM, "Likely debugger or anti-analysis checks."),
]


class CapaAdapter:
    def analyze(self, strings: list[str]) -> AdapterResult:
        haystack = "\n".join(strings)
        observations: list[Observation] = []
        for required, category, severity, message in CAPABILITIES:
            if all(token in haystack for token in required):
                observations.append(
                    Observation(
                        source="capa-heuristic",
                        category=f"capability:{category}",
                        severity=severity,
                        message=message,
                        evidence={"required_strings": sorted(required)},
                        tags=["static", "capability", category],
                    )
                )
        tool_run = ToolExecution(
            tool="capa",
            status=ToolStatus.PASS,
            summary=f"Derived {len(observations)} heuristic capabilities.",
            details={"capability_count": len(observations)},
        )
        return AdapterResult(observations=observations, tool_run=tool_run)
