from __future__ import annotations

import logging

from ..models import BehaviorEvent, ToolExecution, ToolStatus
from .types import AdapterResult

logger = logging.getLogger(__name__)


class CapeAdapter:
    def analyze(self, enabled: bool) -> AdapterResult:
        if not enabled:
            return AdapterResult(
                tool_run=ToolExecution(
                    tool="cape",
                    status=ToolStatus.UNAVAILABLE,
                    summary="Dynamic detonation disabled by policy.",
                    details={"enabled": False},
                )
            )
        event = BehaviorEvent(
            source="cape-placeholder",
            kind="dynamic_analysis",
            summary="Sample would be submitted to CAPE in a full lab deployment.",
            details={},
        )
        return AdapterResult(
            behavior=[event],
            tool_run=ToolExecution(
                tool="cape",
                status=ToolStatus.UNAVAILABLE,
                summary="No CAPE backend is configured in local mode.",
                details={"enabled": True},
            ),
        )
