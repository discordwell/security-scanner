from __future__ import annotations

from ..models import FunctionSummary, Observation, ObservationSeverity, ToolExecution, ToolStatus
from ..utils import find_suspicious_matches, sha256_text
from .types import AdapterResult


class GhidraAdapter:
    def analyze(self, data: bytes, deep_limit: int) -> AdapterResult:
        matches = find_suspicious_matches(data)[:deep_limit]
        functions: list[FunctionSummary] = []
        observations: list[Observation] = []
        for index, (offset, needle, category, message) in enumerate(matches):
            start = max(0, offset - 0x80)
            end = min(len(data), offset + 0x180)
            region = data[start:end]
            normalized_hash = sha256_text(f"{category}:{offset}:{region[:64].hex()}")
            symbol = f"suspect_region_{index}"
            functions.append(
                FunctionSummary(
                    symbol=symbol,
                    start_address=hex(start),
                    end_address=hex(end),
                    triage_score=0.9 - (index * 0.05),
                    reason=message,
                    normalized_hash=normalized_hash,
                    decompiled=False,
                    evidence={"match": needle.decode("utf-8", errors="replace"), "offset": offset},
                )
            )
            observations.append(
                Observation(
                    source="ghidra-heuristic",
                    category="triage:function",
                    severity=ObservationSeverity.MEDIUM,
                    message=f"Promoted {symbol} for selective decompilation because of {needle.decode('utf-8', errors='replace')}.",
                    evidence={"offset": offset, "symbol": symbol},
                    addresses=[hex(start), hex(end)],
                    tags=["static", "decompile", category],
                )
            )
        tool_run = ToolExecution(
            tool="ghidra",
            status=ToolStatus.PASS,
            summary=f"Promoted {len(functions)} suspicious regions for deep analysis.",
            details={"promoted_regions": len(functions)},
        )
        return AdapterResult(observations=observations, functions=functions, tool_run=tool_run)
