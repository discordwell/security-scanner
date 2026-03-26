from __future__ import annotations

import logging

from ..models import Observation, ObservationSeverity, ToolExecution, ToolStatus
from ..utils import find_suspicious_matches
from .types import AdapterResult

logger = logging.getLogger(__name__)


class YaraAdapter:
    def analyze(self, data: bytes) -> AdapterResult:
        observations: list[Observation] = []
        for offset, needle, category, message in find_suspicious_matches(data):
            observations.append(
                Observation(
                    source="yara-heuristic",
                    category=f"rule:{category}",
                    severity=ObservationSeverity.MEDIUM,
                    message=f"Matched heuristic rule on {needle.decode('utf-8', errors='replace')}: {message}.",
                    evidence={"offset": offset, "match": needle.decode("utf-8", errors="replace")},
                    addresses=[hex(offset)],
                    tags=["static", "rule", category],
                )
            )
        tool_run = ToolExecution(
            tool="yara",
            status=ToolStatus.PASS,
            summary=f"Executed {len(observations)} heuristic YARA-style matches.",
            details={"match_count": len(observations)},
        )
        return AdapterResult(observations=observations, tool_run=tool_run)
