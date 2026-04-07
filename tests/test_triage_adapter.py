"""Tests for the Triage cloud sandbox adapter."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from security_scanner.adapters.triage import TriageAdapter
from security_scanner.models import ToolStatus


MOCK_TRIAGE_REPORT = {
    "analysis": {"score": 8, "family": ["emotet"]},
    "signatures": [
        {"name": "process_injection", "desc": "Injects code into another process", "score": 9},
        {"name": "anti_debug", "desc": "Detects debugger presence", "score": 5},
    ],
    "targets": [
        {
            "iocs": {
                "domains": ["evil.example.com"],
                "ips": ["45.33.32.156"],
            },
            "tasks": {
                "1": {"name": "sample.exe", "pid": 1234},
            },
        }
    ],
    "extracted": [
        {"config": {"family": "emotet", "c2": ["10.0.0.1:443"]}},
    ],
    "dropped": [
        {"filename": "payload.dll", "kind": "pe", "sha256": "abc123"},
    ],
}


# -- Stub behavior --


def test_triage_disabled():
    result = TriageAdapter().analyze(enabled=False)
    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.tool_run.details.get("enabled") is False


def test_triage_no_api_key():
    result = TriageAdapter().analyze(enabled=True)
    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.tool_run.details.get("enabled") is True
    assert len(result.behavior) == 1
    assert result.behavior[0].source == "triage-placeholder"


def test_triage_no_data():
    result = TriageAdapter(api_key="test-key").analyze(enabled=True, data=None)
    assert result.tool_run.status == ToolStatus.UNAVAILABLE


# -- Mocked real flow --


def test_triage_full_flow():
    """Test submit → poll → report parsing."""
    adapter = TriageAdapter(api_key="test-key", api_url="http://triage.test", poll_interval=0)

    call_count = 0

    def mock_request(method, path, **kwargs):
        nonlocal call_count
        call_count += 1
        if method == "POST" and path.endswith("/samples"):
            return {"id": "sample-123"}
        elif "status" in path:
            return {"status": "reported"}
        elif "overview.json" in path:
            return MOCK_TRIAGE_REPORT
        return {}

    with patch.object(adapter, "_request", side_effect=mock_request):
        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100)

    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "triage-api"
    assert result.tool_run.details["score"] == 8

    # Check observations
    sources = [obs.source for obs in result.observations]
    assert all(s == "triage" for s in sources)

    categories = [obs.category for obs in result.observations]
    assert "sandbox:score" in categories
    assert "signature:process_injection" in categories
    assert "signature:anti_debug" in categories
    assert "network:dns" in categories
    assert "network:ip" in categories
    assert "extracted:config" in categories
    assert "dropped:file" in categories

    # High score should produce HIGH observation
    score_obs = [o for o in result.observations if o.category == "sandbox:score"]
    assert score_obs[0].severity.value == "high"

    # Behavior events
    assert len(result.behavior) >= 1

    # Family detection
    assert result.tool_run.details["family"] == ["emotet"]


def test_triage_medium_score():
    """Score 4-6 should produce MEDIUM observation."""
    adapter = TriageAdapter(api_key="test-key", poll_interval=0)
    report = {**MOCK_TRIAGE_REPORT, "analysis": {"score": 5, "family": []}}

    def mock_request(method, path, **kwargs):
        if method == "POST":
            return {"id": "s1"}
        if "status" in path:
            return {"status": "reported"}
        return report

    with patch.object(adapter, "_request", side_effect=mock_request):
        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100)

    score_obs = [o for o in result.observations if o.category == "sandbox:score"]
    assert score_obs[0].severity.value == "medium"


def test_triage_low_score_no_score_obs():
    """Score < 4 should not produce a score observation."""
    adapter = TriageAdapter(api_key="test-key", poll_interval=0)
    report = {
        "analysis": {"score": 2, "family": []},
        "signatures": [],
        "targets": [],
        "extracted": [],
        "dropped": [],
    }

    def mock_request(method, path, **kwargs):
        if method == "POST":
            return {"id": "s1"}
        if "status" in path:
            return {"status": "reported"}
        return report

    with patch.object(adapter, "_request", side_effect=mock_request):
        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100)

    score_obs = [o for o in result.observations if o.category == "sandbox:score"]
    assert len(score_obs) == 0


def test_triage_failed_status():
    """Triage reports 'failed' status → returns None, falls back to stub."""
    adapter = TriageAdapter(api_key="test-key", poll_interval=0)

    def mock_request(method, path, **kwargs):
        if method == "POST":
            return {"id": "s1"}
        return {"status": "failed"}

    with patch.object(adapter, "_request", side_effect=mock_request):
        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100)

    assert result.tool_run.status == ToolStatus.UNAVAILABLE


def test_triage_network_error():
    """URLError during submission falls back to stub."""
    import urllib.error

    adapter = TriageAdapter(api_key="test-key", poll_interval=0)

    with patch.object(adapter, "_request", side_effect=urllib.error.URLError("connection refused")):
        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100)

    assert result.tool_run.status == ToolStatus.UNAVAILABLE


def test_triage_no_sample_id():
    """Missing sample ID in response falls back to stub."""
    adapter = TriageAdapter(api_key="test-key", poll_interval=0)

    with patch.object(adapter, "_request", return_value={}):
        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100)

    assert result.tool_run.status == ToolStatus.UNAVAILABLE
