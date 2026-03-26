"""Tests for real YARA integration.

These tests use pytest.importorskip to only run when yara-python is installed.
Run with: uv run --extra dev --extra tools pytest tests/test_yara_real.py
"""
from __future__ import annotations

import pytest

yara = pytest.importorskip("yara")

from pathlib import Path

from security_scanner.adapters.yara import YaraAdapter
from security_scanner.models import ToolStatus


RULES_DIR = Path(__file__).resolve().parent.parent / "data" / "yara_rules"


@pytest.fixture()
def yara_adapter():
    return YaraAdapter(rules_dir=RULES_DIR)


@pytest.mark.integration
def test_yara_real_scan_detects_injection(yara_adapter):
    data = (
        b"MZ" + b"\x00" * 64
        + b"CreateRemoteThread"
        + b"WriteProcessMemory"
        + b"VirtualAllocEx"
        + b"\x00" * 256
    )
    result = yara_adapter.analyze(data)
    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "yara-python"
    assert len(result.observations) > 0
    assert any(obs.source == "yara" for obs in result.observations)
    categories = [obs.category for obs in result.observations]
    assert any("process_injection" in cat for cat in categories)


@pytest.mark.integration
def test_yara_real_scan_benign_no_matches(yara_adapter):
    data = b"\x00" * 512
    result = yara_adapter.analyze(data)
    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "yara-python"
    assert result.observations == []


@pytest.mark.integration
def test_yara_real_detects_memory_manipulation(yara_adapter):
    data = b"MZ" + b"\x00" * 64 + b"VirtualAlloc" + b"VirtualProtect" + b"\x00" * 256
    result = yara_adapter.analyze(data)
    categories = [obs.category for obs in result.observations]
    assert any("memory_exec" in cat for cat in categories)


@pytest.mark.integration
def test_yara_real_observations_have_evidence(yara_adapter):
    data = b"CreateRemoteThread" + b"WriteProcessMemory" + b"VirtualAllocEx"
    result = yara_adapter.analyze(data)
    for obs in result.observations:
        assert obs.evidence.get("rule")
        assert obs.source == "yara"


def test_yara_adapter_fallback_without_rules_dir():
    adapter = YaraAdapter(rules_dir=None)
    data = b"CreateRemoteThread" + b"\x00" * 100
    result = adapter.analyze(data)
    assert result.tool_run.details["mode"] == "heuristic"
    assert any(obs.source == "yara-heuristic" for obs in result.observations)


def test_yara_adapter_fallback_with_empty_rules_dir(tmp_path):
    adapter = YaraAdapter(rules_dir=tmp_path)
    data = b"CreateRemoteThread" + b"\x00" * 100
    result = adapter.analyze(data)
    assert result.tool_run.details["mode"] == "heuristic"


def test_yara_adapter_fallback_with_nonexistent_dir():
    adapter = YaraAdapter(rules_dir=Path("/nonexistent/dir"))
    data = b"CreateRemoteThread" + b"\x00" * 100
    result = adapter.analyze(data)
    assert result.tool_run.details["mode"] == "heuristic"
