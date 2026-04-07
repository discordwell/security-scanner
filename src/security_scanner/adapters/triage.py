"""Hatching Triage cloud sandbox adapter.

Submits binaries to the Triage API for dynamic detonation and behavioral analysis.
Free research tier available at https://tria.ge.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request

from ..models import BehaviorEvent, Observation, ObservationSeverity, ToolExecution, ToolStatus
from .types import AdapterResult

logger = logging.getLogger(__name__)


class TriageAdapter:
    def __init__(
        self,
        api_key: str | None = None,
        api_url: str = "https://tria.ge",
        poll_interval: int = 15,
        timeout: int = 600,
    ) -> None:
        self._api_key = api_key
        self._api_url = api_url.rstrip("/")
        self._poll_interval = poll_interval
        self._timeout = timeout

    def analyze(self, enabled: bool, data: bytes | None = None) -> AdapterResult:
        if not enabled:
            return AdapterResult(
                tool_run=ToolExecution(
                    tool="triage",
                    status=ToolStatus.UNAVAILABLE,
                    summary="Dynamic analysis disabled by policy.",
                    details={"enabled": False},
                )
            )

        if self._api_key and data is not None:
            result = self._analyze_with_triage(data)
            if result is not None:
                return result

        event = BehaviorEvent(
            source="triage-placeholder",
            kind="dynamic_analysis",
            summary="Sample would be submitted to Triage cloud sandbox.",
            details={},
        )
        return AdapterResult(
            behavior=[event],
            tool_run=ToolExecution(
                tool="triage",
                status=ToolStatus.UNAVAILABLE,
                summary="No Triage API key configured.",
                details={"enabled": True},
            ),
        )

    def _request(self, method: str, path: str, body: bytes | None = None, content_type: str | None = None) -> dict:
        """Make an authenticated request to the Triage API."""
        url = f"{self._api_url}{path}"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())

    def _analyze_with_triage(self, data: bytes) -> AdapterResult | None:
        try:
            # Submit sample
            boundary = "----TriageScannerBoundary"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="sample.bin"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode() + data + f"\r\n--{boundary}--\r\n".encode()

            submit_result = self._request(
                "POST",
                "/api/v0/samples",
                body=body,
                content_type=f"multipart/form-data; boundary={boundary}",
            )
            sample_id = submit_result.get("id")
            if not sample_id:
                logger.warning("Triage submission did not return a sample ID")
                return None

            logger.info("Triage sample submitted: %s", sample_id)

            # Poll for completion
            deadline = time.monotonic() + self._timeout
            while time.monotonic() < deadline:
                time.sleep(self._poll_interval)
                status_data = self._request("GET", f"/api/v0/samples/{sample_id}/status")
                status = status_data.get("status", "")
                if status == "reported":
                    break
                if status == "failed":
                    logger.warning("Triage analysis failed for %s", sample_id)
                    return None
            else:
                logger.warning("Triage sample %s timed out after %ds", sample_id, self._timeout)
                return None

            # Retrieve report
            report = self._request("GET", f"/api/v0/samples/{sample_id}/overview.json")
            return self._parse_triage_report(report, sample_id)

        except (urllib.error.URLError, json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("Triage analysis failed: %s", exc)
            return None

    def _parse_triage_report(self, report: dict, sample_id: str) -> AdapterResult:
        observations: list[Observation] = []
        behavior_events: list[BehaviorEvent] = []

        # Overall score and classification
        analysis = report.get("analysis", {})
        score = analysis.get("score", 0)
        family = analysis.get("family", [])

        if score >= 7:
            observations.append(
                Observation(
                    source="triage",
                    category="sandbox:score",
                    severity=ObservationSeverity.HIGH,
                    message=f"Triage threat score: {score}/10" + (f" (family: {', '.join(family)})" if family else ""),
                    evidence={"score": score, "family": family, "sample_id": sample_id},
                    tags=["dynamic", "sandbox", "score"],
                )
            )
        elif score >= 4:
            observations.append(
                Observation(
                    source="triage",
                    category="sandbox:score",
                    severity=ObservationSeverity.MEDIUM,
                    message=f"Triage threat score: {score}/10",
                    evidence={"score": score, "family": family, "sample_id": sample_id},
                    tags=["dynamic", "sandbox", "score"],
                )
            )

        # Signatures / TTPs
        for sig in report.get("signatures", []):
            severity = ObservationSeverity.HIGH if sig.get("score", 0) >= 7 else ObservationSeverity.MEDIUM
            observations.append(
                Observation(
                    source="triage",
                    category=f"signature:{sig.get('name', 'unknown')}",
                    severity=severity,
                    message=sig.get("desc", sig.get("name", "Triage signature")),
                    evidence={"name": sig.get("name"), "score": sig.get("score")},
                    tags=["dynamic", "signature"],
                )
            )

        # Network targets
        for target in report.get("targets", []):
            iocs = target.get("iocs", {})
            for domain in iocs.get("domains", []):
                observations.append(
                    Observation(
                        source="triage",
                        category="network:dns",
                        severity=ObservationSeverity.MEDIUM,
                        message=f"DNS resolution: {domain}",
                        evidence={"domain": domain, "sample_id": sample_id},
                        tags=["dynamic", "network"],
                    )
                )
            for ip in iocs.get("ips", []):
                observations.append(
                    Observation(
                        source="triage",
                        category="network:ip",
                        severity=ObservationSeverity.MEDIUM,
                        message=f"Network connection to {ip}",
                        evidence={"ip": ip, "sample_id": sample_id},
                        tags=["dynamic", "network"],
                    )
                )

        # Extracted configs
        for config in report.get("extracted", []):
            config_type = config.get("config", {}).get("family", "unknown")
            observations.append(
                Observation(
                    source="triage",
                    category="extracted:config",
                    severity=ObservationSeverity.HIGH,
                    message=f"Extracted malware config: {config_type}",
                    evidence={"family": config_type, "config": config.get("config", {})},
                    tags=["dynamic", "extracted", "config"],
                )
            )

        # Process events from targets
        for target in report.get("targets", []):
            for proc in target.get("tasks", {}).values() if isinstance(target.get("tasks"), dict) else []:
                behavior_events.append(
                    BehaviorEvent(
                        source="triage",
                        kind="process",
                        summary=f"Process: {proc.get('name', 'unknown')} (PID {proc.get('pid', '?')})",
                        details={"pid": proc.get("pid"), "name": proc.get("name")},
                    )
                )

        # Dropped files
        for dropped in report.get("dropped", []):
            observations.append(
                Observation(
                    source="triage",
                    category="dropped:file",
                    severity=ObservationSeverity.MEDIUM,
                    message=f"Dropped file: {dropped.get('filename', 'unknown')} ({dropped.get('kind', 'unknown')})",
                    evidence={
                        "filename": dropped.get("filename"),
                        "kind": dropped.get("kind"),
                        "sha256": dropped.get("sha256"),
                    },
                    tags=["dynamic", "dropped"],
                )
            )

        tool_run = ToolExecution(
            tool="triage",
            status=ToolStatus.PASS,
            summary=f"Triage analysis {sample_id}: score={score}/10, {len(observations)} observations, {len(behavior_events)} behavior events.",
            details={
                "sample_id": sample_id,
                "mode": "triage-api",
                "score": score,
                "family": family,
                "observation_count": len(observations),
                "behavior_count": len(behavior_events),
            },
        )
        logger.info("Triage analysis complete: sample=%s score=%d observations=%d", sample_id, score, len(observations))
        return AdapterResult(observations=observations, behavior=behavior_events, tool_run=tool_run)
