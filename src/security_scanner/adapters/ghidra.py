from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import tempfile
from pathlib import Path

from ..models import FunctionSummary, Observation, ObservationSeverity, ToolExecution, ToolStatus
from ..utils import find_suspicious_matches, sha256_text
from .types import AdapterResult

logger = logging.getLogger(__name__)


class GhidraAdapter:
    def __init__(
        self,
        ghidra_cmd: str | None = None,
        project_dir: Path | None = None,
        timeout: int = 300,
        max_functions: int = 50,
    ) -> None:
        self._ghidra_cmd = ghidra_cmd
        self._project_dir = project_dir
        self._timeout = timeout
        self._max_functions = max_functions

    def analyze(self, data: bytes, deep_limit: int) -> AdapterResult:
        if self._ghidra_cmd:
            result = self._analyze_with_ghidra(data, deep_limit)
            if result is not None:
                return result
            logger.warning("Ghidra analysis failed, falling back to heuristic")
        return self._analyze_heuristic(data, deep_limit)

    def _analyze_with_ghidra(self, data: bytes, deep_limit: int) -> AdapterResult | None:
        scripts_dir = Path(__file__).resolve().parent.parent.parent.parent / "scripts"
        script_path = scripts_dir / "ghidra_export.py"
        if not script_path.exists():
            logger.warning("Ghidra export script not found at %s", script_path)
            return None

        with tempfile.TemporaryDirectory(prefix="ghidra_") as tmp_dir:
            tmp = Path(tmp_dir)
            sample_path = tmp / "sample.bin"
            sample_path.write_bytes(data)
            output_path = tmp / "output.json"
            project_dir = self._project_dir or tmp / "project"
            project_dir.mkdir(parents=True, exist_ok=True)

            cmd = [
                self._ghidra_cmd,
                str(project_dir),
                "scan_project",
                "-import", str(sample_path),
                "-overwrite",
                "-postScript", str(script_path),
                str(min(deep_limit, self._max_functions)),
                str(output_path),
                "-scriptlog", str(tmp / "script.log"),
                "-deleteProject",
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                )
                if proc.returncode != 0:
                    logger.warning("Ghidra exited with code %d: %s", proc.returncode, proc.stderr[:500])
                    return None

                if not output_path.exists():
                    logger.warning("Ghidra script did not produce output file")
                    return None

                report = json.loads(output_path.read_text())
                return self._parse_ghidra_report(report, data, deep_limit)

            except subprocess.TimeoutExpired:
                logger.warning("Ghidra timed out after %ds", self._timeout)
                return None
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.warning("Failed to parse Ghidra output: %s", exc)
                return None

    def _parse_ghidra_report(
        self, report: dict, data: bytes, deep_limit: int,
    ) -> AdapterResult:
        functions: list[FunctionSummary] = []
        observations: list[Observation] = []
        raw_functions = report.get("functions", [])

        for index, func in enumerate(raw_functions[:deep_limit]):
            decompiled_src = func.get("decompiled")
            if decompiled_src:
                normalized_hash = hashlib.sha256(decompiled_src.encode()).hexdigest()
            else:
                normalized_hash = sha256_text(f"{func['name']}:{func['entry']}")

            functions.append(
                FunctionSummary(
                    symbol=func["name"],
                    start_address=func["entry"],
                    end_address=func["end"],
                    triage_score=max(0.1, 0.9 - (index * 0.02)),
                    reason=f"Ghidra function at {func['entry']}",
                    normalized_hash=normalized_hash,
                    decompiled=decompiled_src is not None,
                    evidence={
                        "size": func.get("size", 0),
                        "calling": func.get("calling", [])[:5],
                        "called_by": func.get("called_by", [])[:5],
                    },
                )
            )

        total_functions = len(raw_functions)
        analyzed_count = len(functions)

        if total_functions > analyzed_count:
            observations.append(
                Observation(
                    source="ghidra",
                    category="coverage_gap",
                    severity=ObservationSeverity.INFO,
                    message=f"Ghidra found {total_functions} functions but only {analyzed_count} were analyzed (limit={deep_limit}).",
                    evidence={
                        "total_functions": total_functions,
                        "analyzed_functions": analyzed_count,
                        "limit": deep_limit,
                    },
                    tags=["static", "coverage"],
                )
            )

        not_decompiled = sum(1 for f in functions if not f.decompiled)
        if not_decompiled > 0:
            observations.append(
                Observation(
                    source="ghidra",
                    category="coverage_gap",
                    severity=ObservationSeverity.INFO,
                    message=f"{not_decompiled} of {analyzed_count} functions could not be decompiled.",
                    evidence={"not_decompiled": not_decompiled},
                    tags=["static", "coverage"],
                )
            )

        tool_run = ToolExecution(
            tool="ghidra",
            status=ToolStatus.PASS,
            summary=f"Ghidra analyzed {analyzed_count} of {total_functions} functions.",
            details={
                "total_functions": total_functions,
                "analyzed_functions": analyzed_count,
                "mode": "ghidra-headless",
            },
        )
        logger.info("Ghidra analysis: %d/%d functions analyzed", analyzed_count, total_functions)
        return AdapterResult(observations=observations, functions=functions, tool_run=tool_run)

    def _analyze_heuristic(self, data: bytes, deep_limit: int) -> AdapterResult:
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
                    triage_score=max(0.1, 0.9 - (index * 0.05)),
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
            details={"promoted_regions": len(functions), "mode": "heuristic"},
        )
        return AdapterResult(observations=observations, functions=functions, tool_run=tool_run)
