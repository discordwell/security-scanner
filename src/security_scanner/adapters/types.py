from __future__ import annotations

from dataclasses import dataclass, field

from ..models import BehaviorEvent, FunctionSummary, Observation, ToolExecution


@dataclass(slots=True)
class AdapterResult:
    observations: list[Observation] = field(default_factory=list)
    functions: list[FunctionSummary] = field(default_factory=list)
    behavior: list[BehaviorEvent] = field(default_factory=list)
    tool_run: ToolExecution | None = None
