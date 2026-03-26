"""Tests for CAPE and DRAKVUF HTTP adapter integration (mocked)."""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

from security_scanner.adapters.cape import CapeAdapter
from security_scanner.adapters.drakvuf import DrakvufAdapter
from security_scanner.models import ObservationSeverity, ToolStatus


# -- CapeAdapter --

MOCK_CAPE_REPORT = {
    "network": {
        "domains": [{"domain": "evil.example", "ip": "1.2.3.4"}],
    },
    "signatures": [
        {"name": "injection", "severity": 3, "description": "Process injection detected", "marks": []},
        {"name": "network", "severity": 2, "description": "Network activity", "marks": []},
    ],
    "behavior": {
        "processes": [
            {"process_name": "sample.exe", "pid": 1234, "ppid": 1000},
        ],
    },
}


def _mock_cape_urlopen(submit_response, status_response, report_response):
    call_count = {"n": 0}

    def side_effect(req, **kwargs):
        call_count["n"] += 1
        url = req if isinstance(req, str) else req.full_url
        mock_resp = MagicMock()
        if "create" in url:
            mock_resp.read.return_value = json.dumps(submit_response).encode()
        elif "view" in url:
            mock_resp.read.return_value = json.dumps(status_response).encode()
        elif "report" in url:
            mock_resp.read.return_value = json.dumps(report_response).encode()
        return mock_resp

    return side_effect


def test_cape_parses_report():
    adapter = CapeAdapter(cape_url="http://cape:8000", poll_interval=0, timeout=5)

    with patch("security_scanner.adapters.cape.urllib.request.urlopen",
               side_effect=_mock_cape_urlopen(
                   {"data": [42]},
                   {"data": {"status": "reported"}},
                   MOCK_CAPE_REPORT,
               )):
        with patch("security_scanner.adapters.cape.time.sleep"):
            result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100)

    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "cape-api"
    assert len(result.observations) >= 2
    assert len(result.behavior) >= 1

    high_obs = [o for o in result.observations if o.severity == ObservationSeverity.HIGH]
    assert len(high_obs) >= 1


def test_cape_disabled():
    adapter = CapeAdapter(cape_url="http://cape:8000")
    result = adapter.analyze(enabled=False)
    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.tool_run.details["enabled"] is False


def test_cape_stub_when_no_url():
    adapter = CapeAdapter(cape_url=None)
    result = adapter.analyze(enabled=True, data=b"MZ")
    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.behavior[0].source == "cape-placeholder"


def test_cape_failure_falls_back():
    import urllib.error
    adapter = CapeAdapter(cape_url="http://cape:8000")

    with patch("security_scanner.adapters.cape.urllib.request.urlopen",
               side_effect=urllib.error.URLError("connection refused")):
        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100)

    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.behavior[0].source == "cape-placeholder"


# -- DrakvufAdapter --

MOCK_DRAKVUF_REPORT = {
    "syscalls": [
        {"name": "NtCreateFile", "pid": 1234},
        {"name": "NtWriteFile", "pid": 1234},
    ],
    "injections": [
        {"type": "process_hollowing", "source_pid": 1234, "target_pid": 5678},
    ],
    "evasions": [
        {"technique": "timing_check", "details": "rdtsc-based timing"},
    ],
}


def _mock_drakvuf_urlopen(submit_response, status_response, report_response):
    def side_effect(req, **kwargs):
        url = req if isinstance(req, str) else req.full_url
        mock_resp = MagicMock()
        if "upload" in url:
            mock_resp.read.return_value = json.dumps(submit_response).encode()
        elif "status" in url:
            mock_resp.read.return_value = json.dumps(status_response).encode()
        elif "report" in url:
            mock_resp.read.return_value = json.dumps(report_response).encode()
        return mock_resp
    return side_effect


def test_drakvuf_parses_report():
    adapter = DrakvufAdapter(drakvuf_url="http://drakvuf:8080", poll_interval=0, timeout=5)

    with patch("security_scanner.adapters.drakvuf.urllib.request.urlopen",
               side_effect=_mock_drakvuf_urlopen(
                   {"task_uid": "abc-123"},
                   {"status": "done"},
                   MOCK_DRAKVUF_REPORT,
               )):
        with patch("security_scanner.adapters.drakvuf.time.sleep"):
            result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100)

    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "drakvuf-api"
    assert len(result.behavior) >= 2
    assert len(result.observations) >= 2

    injection_obs = [o for o in result.observations if o.category == "injection"]
    assert len(injection_obs) >= 1
    assert injection_obs[0].severity == ObservationSeverity.HIGH


def test_drakvuf_disabled():
    adapter = DrakvufAdapter(drakvuf_url="http://drakvuf:8080")
    result = adapter.analyze(enabled=False)
    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.tool_run.details["enabled"] is False


def test_drakvuf_stub_when_no_url():
    adapter = DrakvufAdapter(drakvuf_url=None)
    result = adapter.analyze(enabled=True, data=b"MZ")
    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.behavior[0].source == "drakvuf-placeholder"


def test_drakvuf_failure_falls_back():
    import urllib.error
    adapter = DrakvufAdapter(drakvuf_url="http://drakvuf:8080")

    with patch("security_scanner.adapters.drakvuf.urllib.request.urlopen",
               side_effect=urllib.error.URLError("connection refused")):
        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100)

    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.behavior[0].source == "drakvuf-placeholder"
