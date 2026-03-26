from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request

from ..models import BehaviorEvent, Observation, ObservationSeverity, ToolExecution, ToolStatus
from .types import AdapterResult

logger = logging.getLogger(__name__)


class DrakvufAdapter:
    def __init__(self, drakvuf_url: str | None = None, poll_interval: int = 10, timeout: int = 300) -> None:
        self._drakvuf_url = drakvuf_url
        self._poll_interval = poll_interval
        self._timeout = timeout

    def analyze(self, enabled: bool, data: bytes | None = None) -> AdapterResult:
        if not enabled:
            return AdapterResult(
                tool_run=ToolExecution(
                    tool="drakvuf",
                    status=ToolStatus.UNAVAILABLE,
                    summary="Stealth dynamic lane disabled by policy.",
                    details={"enabled": False},
                )
            )

        if self._drakvuf_url and data is not None:
            result = self._analyze_with_drakvuf(data)
            if result is not None:
                return result

        event = BehaviorEvent(
            source="drakvuf-placeholder",
            kind="stealth_dynamic_analysis",
            summary="Sample would be submitted to DRAKVUF for anti-evasion analysis in a full lab deployment.",
            details={},
        )
        return AdapterResult(
            behavior=[event],
            tool_run=ToolExecution(
                tool="drakvuf",
                status=ToolStatus.UNAVAILABLE,
                summary="No DRAKVUF backend is configured in local mode.",
                details={"enabled": True},
            ),
        )

    def _analyze_with_drakvuf(self, data: bytes) -> AdapterResult | None:
        try:
            boundary = "----SecurityScannerBoundary"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="sample.bin"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode() + data + f"\r\n--{boundary}--\r\n".encode()

            req = urllib.request.Request(
                f"{self._drakvuf_url}/upload",
                data=body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=30)
            submit_result = json.loads(resp.read())
            task_id = submit_result.get("task_uid", submit_result.get("task_id"))
            if not task_id:
                logger.warning("DRAKVUF submission did not return a task ID")
                return None

            logger.info("DRAKVUF task submitted: %s", task_id)

            # Poll for completion
            deadline = time.monotonic() + self._timeout
            while time.monotonic() < deadline:
                time.sleep(self._poll_interval)
                status_resp = urllib.request.urlopen(
                    f"{self._drakvuf_url}/status/{task_id}", timeout=10,
                )
                status_data = json.loads(status_resp.read())
                if status_data.get("status") == "done":
                    break
            else:
                logger.warning("DRAKVUF task %s timed out", task_id)
                return None

            # Retrieve report
            report_resp = urllib.request.urlopen(
                f"{self._drakvuf_url}/report/{task_id}", timeout=30,
            )
            report = json.loads(report_resp.read())
            return self._parse_drakvuf_report(report, task_id)

        except (urllib.error.URLError, json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("DRAKVUF analysis failed: %s", exc)
            return None

    def _parse_drakvuf_report(self, report: dict, task_id: str) -> AdapterResult:
        observations: list[Observation] = []
        behavior_events: list[BehaviorEvent] = []

        # Syscall traces
        for syscall in report.get("syscalls", [])[:50]:
            behavior_events.append(
                BehaviorEvent(
                    source="drakvuf",
                    kind="syscall",
                    summary=f"Syscall: {syscall.get('name', 'unknown')}",
                    details=syscall,
                )
            )

        # Injection attempts
        for injection in report.get("injections", []):
            observations.append(
                Observation(
                    source="drakvuf",
                    category="injection",
                    severity=ObservationSeverity.HIGH,
                    message=f"Process injection detected: {injection.get('type', 'unknown')}",
                    evidence=injection,
                    tags=["dynamic", "injection", "anti-evasion"],
                )
            )

        # Anti-evasion detections
        for evasion in report.get("evasions", []):
            observations.append(
                Observation(
                    source="drakvuf",
                    category="anti_analysis",
                    severity=ObservationSeverity.MEDIUM,
                    message=f"Evasion technique: {evasion.get('technique', 'unknown')}",
                    evidence=evasion,
                    tags=["dynamic", "anti-analysis"],
                )
            )

        tool_run = ToolExecution(
            tool="drakvuf",
            status=ToolStatus.PASS,
            summary=f"DRAKVUF task {task_id}: {len(observations)} observations, {len(behavior_events)} syscalls.",
            details={
                "task_id": task_id,
                "mode": "drakvuf-api",
                "observation_count": len(observations),
                "syscall_count": len(behavior_events),
            },
        )
        logger.info("DRAKVUF analysis complete: task=%s observations=%d", task_id, len(observations))
        return AdapterResult(observations=observations, behavior=behavior_events, tool_run=tool_run)
