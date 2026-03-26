"""Tests for real YARA integration.

Integration tests require yara-python and are marked with @pytest.mark.integration.
Fallback tests run without yara-python.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from security_scanner.adapters.yara import YaraAdapter
from security_scanner.models import ToolStatus

RULES_DIR = Path(__file__).resolve().parent.parent / "data" / "yara_rules"


# -- Fallback tests (always run) --

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


# -- Integration tests (require yara-python) --

try:
    import yara as _yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

needs_yara = pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")


@pytest.fixture()
def yara_adapter():
    return YaraAdapter(rules_dir=RULES_DIR)


@needs_yara
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


@needs_yara
@pytest.mark.integration
def test_yara_real_scan_benign_no_matches(yara_adapter):
    data = b"\x00" * 512
    result = yara_adapter.analyze(data)
    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "yara-python"
    assert result.observations == []


@needs_yara
@pytest.mark.integration
def test_yara_real_detects_memory_manipulation(yara_adapter):
    data = b"MZ" + b"\x00" * 64 + b"VirtualAlloc" + b"VirtualProtect" + b"\x00" * 256
    result = yara_adapter.analyze(data)
    categories = [obs.category for obs in result.observations]
    assert any("memory_exec" in cat for cat in categories)


@needs_yara
@pytest.mark.integration
def test_yara_real_observations_have_evidence(yara_adapter):
    data = b"CreateRemoteThread" + b"WriteProcessMemory" + b"VirtualAllocEx"
    result = yara_adapter.analyze(data)
    for obs in result.observations:
        assert obs.evidence.get("rule")
        assert obs.source == "yara"
