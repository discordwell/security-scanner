from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

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

CAPA_SEVERITY_MAP: dict[str, ObservationSeverity] = {
    "attack": ObservationSeverity.HIGH,
    "mbc": ObservationSeverity.MEDIUM,
    "capability": ObservationSeverity.MEDIUM,
}


class CapaAdapter:
    def __init__(self, capa_cmd: str | None = None) -> None:
        self._capa_cmd = capa_cmd
        if capa_cmd is None and shutil.which("capa"):
            self._capa_cmd = "capa"

    def analyze(self, strings: list[str], data: bytes | None = None) -> AdapterResult:
        if self._capa_cmd and data is not None:
            result = self._analyze_with_capa(data)
            if result is not None:
                return result
        return self._analyze_heuristic(strings)

    def _analyze_with_capa(self, data: bytes) -> AdapterResult | None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        try:
            proc = subprocess.run(
                [self._capa_cmd, "-j", str(tmp_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                logger.warning("capa exited with code %d: %s", proc.returncode, proc.stderr[:500])
                return None
            report = json.loads(proc.stdout)
            return self._parse_capa_report(report)
        except subprocess.TimeoutExpired:
            logger.warning("capa timed out")
            return None
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("Failed to parse capa output: %s", exc)
            return None
        finally:
            tmp_path.unlink(missing_ok=True)

    def _parse_capa_report(self, report: dict) -> AdapterResult:
        observations: list[Observation] = []
        rules = report.get("rules", {})
        for rule_name, rule_data in rules.items():
            meta = rule_data.get("meta", {})
            namespace = meta.get("namespace", "")
            att_ck = meta.get("att&ck", meta.get("attack", []))
            mbc = meta.get("mbc", [])

            if att_ck:
                severity = ObservationSeverity.HIGH
            elif mbc:
                severity = ObservationSeverity.MEDIUM
            else:
                severity = ObservationSeverity.MEDIUM

            category = namespace.split("/")[0] if namespace else "capability"
            observations.append(
                Observation(
                    source="capa",
                    category=f"capability:{category}",
                    severity=severity,
                    message=f"capa: {rule_name}",
                    evidence={
                        "rule": rule_name,
                        "namespace": namespace,
                        "att&ck": att_ck if isinstance(att_ck, list) else [att_ck],
                        "mbc": mbc if isinstance(mbc, list) else [mbc],
                    },
                    tags=["static", "capability", category],
                )
            )
        tool_run = ToolExecution(
            tool="capa",
            status=ToolStatus.PASS,
            summary=f"capa identified {len(observations)} capabilities.",
            details={"capability_count": len(observations), "mode": "capa-cli"},
        )
        logger.info("capa analysis: %d capabilities identified", len(observations))
        return AdapterResult(observations=observations, tool_run=tool_run)

    def _analyze_heuristic(self, strings: list[str]) -> AdapterResult:
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
            details={"capability_count": len(observations), "mode": "heuristic"},
        )
        return AdapterResult(observations=observations, tool_run=tool_run)
