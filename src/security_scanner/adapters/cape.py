from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path

from ..models import BehaviorEvent, Observation, ObservationSeverity, ToolExecution, ToolStatus
from .types import AdapterResult

logger = logging.getLogger(__name__)


class CapeAdapter:
    def __init__(self, cape_url: str | None = None, poll_interval: int = 10, timeout: int = 300) -> None:
        self._cape_url = cape_url
        self._poll_interval = poll_interval
        self._timeout = timeout

    def analyze(self, enabled: bool, data: bytes | None = None) -> AdapterResult:
        if not enabled:
            return AdapterResult(
                tool_run=ToolExecution(
                    tool="cape",
                    status=ToolStatus.UNAVAILABLE,
                    summary="Dynamic detonation disabled by policy.",
                    details={"enabled": False},
                )
            )

        if self._cape_url and data is not None:
            result = self._analyze_with_cape(data)
            if result is not None:
                return result

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

    def _analyze_with_cape(self, data: bytes) -> AdapterResult | None:
        try:
            # Submit sample
            boundary = "----SecurityScannerBoundary"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="sample.bin"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode() + data + f"\r\n--{boundary}--\r\n".encode()

            req = urllib.request.Request(
                f"{self._cape_url}/api/tasks/create/file/",
                data=body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=30)
            submit_result = json.loads(resp.read())
            task_id = submit_result.get("data", submit_result.get("task_id"))
            if isinstance(task_id, list):
                task_id = task_id[0]
            if not task_id:
                logger.warning("CAPE submission did not return a task ID")
                return None

            logger.info("CAPE task submitted: %s", task_id)

            # Poll for completion
            deadline = time.monotonic() + self._timeout
            while time.monotonic() < deadline:
                time.sleep(self._poll_interval)
                status_resp = urllib.request.urlopen(
                    f"{self._cape_url}/api/tasks/view/{task_id}/", timeout=10,
                )
                status_data = json.loads(status_resp.read())
                task_status = status_data.get("data", {}).get("status", "")
                if task_status == "reported":
                    break
            else:
                logger.warning("CAPE task %s timed out", task_id)
                return None

            # Retrieve report
            report_resp = urllib.request.urlopen(
                f"{self._cape_url}/api/tasks/report/{task_id}/", timeout=30,
            )
            report = json.loads(report_resp.read())
            return self._parse_cape_report(report, task_id)

        except (urllib.error.URLError, json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("CAPE analysis failed: %s", exc)
            return None

    def _parse_cape_report(self, report: dict, task_id: str) -> AdapterResult:
        observations: list[Observation] = []
        behavior_events: list[BehaviorEvent] = []

        # Network IOCs
        network = report.get("network", {})
        for domain in network.get("domains", []):
            observations.append(
                Observation(
                    source="cape",
                    category="network:dns",
                    severity=ObservationSeverity.MEDIUM,
                    message=f"DNS resolution: {domain.get('domain', 'unknown')}",
                    evidence={"domain": domain},
                    tags=["dynamic", "network"],
                )
            )

        # Signatures
        for sig in report.get("signatures", []):
            severity = ObservationSeverity.HIGH if sig.get("severity", 0) >= 3 else ObservationSeverity.MEDIUM
            observations.append(
                Observation(
                    source="cape",
                    category=f"signature:{sig.get('name', 'unknown')}",
                    severity=severity,
                    message=sig.get("description", sig.get("name", "Unknown signature")),
                    evidence={"marks": sig.get("marks", [])[:5]},
                    tags=["dynamic", "signature"],
                )
            )

        # Process events
        for proc in report.get("behavior", {}).get("processes", []):
            behavior_events.append(
                BehaviorEvent(
                    source="cape",
                    kind="process",
                    summary=f"Process: {proc.get('process_name', 'unknown')} (PID {proc.get('pid', '?')})",
                    details={"pid": proc.get("pid"), "ppid": proc.get("ppid")},
                )
            )

        tool_run = ToolExecution(
            tool="cape",
            status=ToolStatus.PASS,
            summary=f"CAPE task {task_id}: {len(observations)} observations, {len(behavior_events)} behavior events.",
            details={
                "task_id": task_id,
                "mode": "cape-api",
                "observation_count": len(observations),
                "behavior_count": len(behavior_events),
            },
        )
        logger.info("CAPE analysis complete: task=%s observations=%d", task_id, len(observations))
        return AdapterResult(observations=observations, behavior=behavior_events, tool_run=tool_run)
