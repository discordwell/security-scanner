"""Tests for Ghidra adapter integration.

Tests the Ghidra headless subprocess integration by mocking subprocess.run,
coverage_gap observation emission, and the heuristic fallback.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from security_scanner.adapters.ghidra import GhidraAdapter
from security_scanner.models import ToolStatus


MOCK_GHIDRA_REPORT = {
    "functions": [
        {
            "name": "main",
            "entry": "0x00401000",
            "end": "0x004010ff",
            "size": 256,
            "decompiled": "int main(int argc, char **argv) { return 0; }",
            "calling": ["printf", "exit"],
            "called_by": ["_start"],
        },
        {
            "name": "suspicious_func",
            "entry": "0x00402000",
            "end": "0x004020ff",
            "size": 256,
            "decompiled": "void suspicious_func() { VirtualAlloc(0, 0x1000, 0x3000, 0x40); }",
            "calling": ["VirtualAlloc"],
            "called_by": ["main"],
        },
        {
            "name": "helper",
            "entry": "0x00403000",
            "end": "0x004030ff",
            "size": 128,
            "decompiled": None,
            "calling": [],
            "called_by": ["main"],
        },
    ],
}


def _mock_ghidra_subprocess(output_report, returncode=0):
    def side_effect(cmd, **kwargs):
        # Find the output path in the command args (after ghidra_export.py, max_functions)
        for i, arg in enumerate(cmd):
            if arg.endswith(".json"):
                Path(arg).write_text(json.dumps(output_report))
                break
        return type("Proc", (), {"returncode": returncode, "stdout": "", "stderr": ""})()
    return side_effect


def test_ghidra_real_parses_report():
    adapter = GhidraAdapter(ghidra_cmd="/opt/ghidra/support/analyzeHeadless")

    with patch("security_scanner.adapters.ghidra.subprocess.run", side_effect=_mock_ghidra_subprocess(MOCK_GHIDRA_REPORT)):
        result = adapter.analyze(data=b"MZ" + b"\x00" * 100, deep_limit=10)

    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "ghidra-headless"
    assert len(result.functions) == 3

    # Check function properties
    main_func = next(f for f in result.functions if f.symbol == "main")
    assert main_func.decompiled is True
    assert main_func.start_address == "0x00401000"

    helper_func = next(f for f in result.functions if f.symbol == "helper")
    assert helper_func.decompiled is False


def test_ghidra_emits_coverage_gap_when_over_limit():
    large_report = {
        "functions": [
            {
                "name": f"func_{i}",
                "entry": f"0x{0x401000 + i * 0x100:08x}",
                "end": f"0x{0x401000 + i * 0x100 + 0xff:08x}",
                "size": 256,
                "decompiled": f"void func_{i}() {{}}",
                "calling": [],
                "called_by": [],
            }
            for i in range(20)
        ],
    }
    adapter = GhidraAdapter(ghidra_cmd="/opt/ghidra/support/analyzeHeadless")

    with patch("security_scanner.adapters.ghidra.subprocess.run", side_effect=_mock_ghidra_subprocess(large_report)):
        result = adapter.analyze(data=b"MZ" + b"\x00" * 100, deep_limit=5)

    assert len(result.functions) == 5
    coverage_gaps = [obs for obs in result.observations if obs.category == "coverage_gap"]
    assert len(coverage_gaps) >= 1
    assert any("20 functions" in obs.message for obs in coverage_gaps)


def test_ghidra_emits_coverage_gap_for_undecompiled():
    adapter = GhidraAdapter(ghidra_cmd="/opt/ghidra/support/analyzeHeadless")

    with patch("security_scanner.adapters.ghidra.subprocess.run", side_effect=_mock_ghidra_subprocess(MOCK_GHIDRA_REPORT)):
        result = adapter.analyze(data=b"MZ" + b"\x00" * 100, deep_limit=10)

    coverage_gaps = [obs for obs in result.observations if obs.category == "coverage_gap"]
    assert any("could not be decompiled" in obs.message for obs in coverage_gaps)


def test_ghidra_failure_falls_back_to_heuristic():
    adapter = GhidraAdapter(ghidra_cmd="/opt/ghidra/support/analyzeHeadless")

    with patch("security_scanner.adapters.ghidra.subprocess.run", side_effect=_mock_ghidra_subprocess({}, returncode=1)):
        data = b"CreateRemoteThread" + b"\x00" * 100
        result = adapter.analyze(data=data, deep_limit=8)

    assert result.tool_run.details["mode"] == "heuristic"
    assert any(obs.source == "ghidra-heuristic" for obs in result.observations)


def test_ghidra_timeout_falls_back():
    import subprocess

    adapter = GhidraAdapter(ghidra_cmd="/opt/ghidra/support/analyzeHeadless", timeout=1)

    with patch("security_scanner.adapters.ghidra.subprocess.run", side_effect=subprocess.TimeoutExpired("ghidra", 1)):
        data = b"CreateRemoteThread" + b"\x00" * 100
        result = adapter.analyze(data=data, deep_limit=8)

    assert result.tool_run.details["mode"] == "heuristic"


def test_ghidra_heuristic_when_no_cmd():
    adapter = GhidraAdapter(ghidra_cmd=None)
    data = b"CreateRemoteThread" + b"\x00" * 100
    result = adapter.analyze(data=data, deep_limit=8)
    assert result.tool_run.details["mode"] == "heuristic"
    assert len(result.functions) > 0


def test_ghidra_normalized_hash_differs_for_decompiled():
    adapter = GhidraAdapter(ghidra_cmd="/opt/ghidra/support/analyzeHeadless")

    with patch("security_scanner.adapters.ghidra.subprocess.run", side_effect=_mock_ghidra_subprocess(MOCK_GHIDRA_REPORT)):
        result = adapter.analyze(data=b"MZ" + b"\x00" * 100, deep_limit=10)

    hashes = [f.normalized_hash for f in result.functions]
    assert len(set(hashes)) == len(hashes), "All normalized hashes should be unique"
