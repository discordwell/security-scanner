"""Tests for capa adapter integration.

Tests the capa CLI subprocess integration by mocking subprocess.run,
and the heuristic fallback when capa is not available.
"""
from __future__ import annotations

import json
from unittest.mock import patch

from security_scanner.adapters.capa import CapaAdapter
from security_scanner.models import ObservationSeverity, ToolStatus


MOCK_CAPA_REPORT = {
    "rules": {
        "create process": {
            "meta": {
                "namespace": "host-interaction/process/create",
                "att&ck": [{"technique": "T1106", "name": "Native API"}],
                "mbc": [],
            },
        },
        "receive data": {
            "meta": {
                "namespace": "communication/receive",
                "att&ck": [],
                "mbc": [{"objective": "Communication", "behavior": "Receive Data"}],
            },
        },
        "anti-debugging": {
            "meta": {
                "namespace": "anti-analysis/anti-debugging",
                "att&ck": [{"technique": "T1622", "name": "Debugger Evasion"}],
                "mbc": [],
            },
        },
    },
}


def test_capa_cli_parses_report():
    adapter = CapaAdapter(capa_cmd="/usr/bin/capa")

    mock_proc = type("Proc", (), {"returncode": 0, "stdout": json.dumps(MOCK_CAPA_REPORT), "stderr": ""})()

    with patch("security_scanner.adapters.capa.subprocess.run", return_value=mock_proc):
        result = adapter.analyze(strings=[], data=b"MZ" + b"\x00" * 100)

    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "capa-cli"
    assert len(result.observations) == 3

    sources = {obs.source for obs in result.observations}
    assert sources == {"capa"}

    # ATT&CK-tagged rules should be HIGH
    att_ck_obs = [obs for obs in result.observations if obs.evidence.get("att&ck")]
    for obs in att_ck_obs:
        if any(obs.evidence["att&ck"]):
            assert obs.severity == ObservationSeverity.HIGH


def test_capa_cli_failure_falls_back_to_heuristic():
    adapter = CapaAdapter(capa_cmd="/usr/bin/capa")

    mock_proc = type("Proc", (), {"returncode": 1, "stdout": "", "stderr": "error"})()

    with patch("security_scanner.adapters.capa.subprocess.run", return_value=mock_proc):
        strings = ["CreateRemoteThread", "WriteProcessMemory"]
        result = adapter.analyze(strings=strings, data=b"MZ" + b"\x00" * 100)

    assert result.tool_run.details["mode"] == "heuristic"
    assert any(obs.source == "capa-heuristic" for obs in result.observations)


def test_capa_cli_timeout_falls_back():
    import subprocess

    adapter = CapaAdapter(capa_cmd="/usr/bin/capa")

    with patch("security_scanner.adapters.capa.subprocess.run", side_effect=subprocess.TimeoutExpired("capa", 120)):
        strings = ["CreateRemoteThread", "WriteProcessMemory"]
        result = adapter.analyze(strings=strings, data=b"MZ" + b"\x00" * 100)

    assert result.tool_run.details["mode"] == "heuristic"


def test_capa_heuristic_without_capa_cmd():
    adapter = CapaAdapter(capa_cmd=None)
    # Force no capa on PATH
    with patch("security_scanner.adapters.capa.shutil.which", return_value=None):
        adapter = CapaAdapter(capa_cmd=None)
    strings = ["CreateRemoteThread", "WriteProcessMemory"]
    result = adapter.analyze(strings=strings, data=b"MZ" + b"\x00" * 100)
    assert result.tool_run.details["mode"] == "heuristic"


def test_capa_heuristic_without_data():
    adapter = CapaAdapter(capa_cmd="/usr/bin/capa")
    strings = ["CreateRemoteThread", "WriteProcessMemory"]
    result = adapter.analyze(strings=strings, data=None)
    assert result.tool_run.details["mode"] == "heuristic"
