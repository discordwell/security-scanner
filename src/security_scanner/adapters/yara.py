from __future__ import annotations

import logging
from pathlib import Path

from ..models import Observation, ObservationSeverity, ToolExecution, ToolStatus
from ..utils import find_suspicious_matches
from .types import AdapterResult

logger = logging.getLogger(__name__)

try:
    import yara as _yara

    HAS_YARA = True
except ImportError:
    HAS_YARA = False

SEVERITY_MAP: dict[str, ObservationSeverity] = {
    "critical": ObservationSeverity.CRITICAL,
    "high": ObservationSeverity.HIGH,
    "medium": ObservationSeverity.MEDIUM,
    "low": ObservationSeverity.LOW,
    "info": ObservationSeverity.INFO,
}


class YaraAdapter:
    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir
        self._compiled_rules = None
        if HAS_YARA and rules_dir and rules_dir.is_dir():
            rule_files = {
                f.stem: str(f)
                for f in sorted(rules_dir.glob("*.yar"))
                if f.is_file()
            }
            if rule_files:
                try:
                    self._compiled_rules = _yara.compile(filepaths=rule_files)
                    logger.info("Compiled %d YARA rule files from %s", len(rule_files), rules_dir)
                except _yara.Error as exc:
                    logger.warning("Failed to compile YARA rules: %s", exc)

    def analyze(self, data: bytes) -> AdapterResult:
        if self._compiled_rules is not None:
            return self._analyze_with_yara(data)
        return self._analyze_heuristic(data)

    def _analyze_with_yara(self, data: bytes) -> AdapterResult:
        observations: list[Observation] = []
        matches = self._compiled_rules.match(data=data)
        for match in matches:
            meta = match.meta
            severity = SEVERITY_MAP.get(
                str(meta.get("severity", "medium")).lower(),
                ObservationSeverity.MEDIUM,
            )
            category = meta.get("category", match.rule)
            description = meta.get("description", match.rule)
            matched_strings = []
            for string_match in match.strings:
                for instance in string_match.instances:
                    matched_strings.append({
                        "offset": instance.offset,
                        "identifier": string_match.identifier,
                        "data": instance.matched_data.decode("utf-8", errors="replace"),
                    })
            observations.append(
                Observation(
                    source="yara",
                    category=f"rule:{category}",
                    severity=severity,
                    message=f"YARA rule {match.rule}: {description}",
                    evidence={
                        "rule": match.rule,
                        "tags": list(match.tags),
                        "strings": matched_strings[:10],
                    },
                    addresses=[
                        hex(inst.offset)
                        for sm in match.strings[:10]
                        for inst in sm.instances[:3]
                    ],
                    tags=["static", "rule", category],
                )
            )
        tool_run = ToolExecution(
            tool="yara",
            status=ToolStatus.PASS,
            summary=f"YARA scan matched {len(observations)} rules.",
            details={"match_count": len(observations), "mode": "yara-python"},
        )
        logger.info("YARA scan: %d rule matches", len(observations))
        return AdapterResult(observations=observations, tool_run=tool_run)

    def _analyze_heuristic(self, data: bytes) -> AdapterResult:
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
            details={"match_count": len(observations), "mode": "heuristic"},
        )
        return AdapterResult(observations=observations, tool_run=tool_run)
