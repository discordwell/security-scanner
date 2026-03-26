"""Tests for the angr adapter.

Mocks angr internals for unit tests. Real integration tests require
angr installed: uv run --extra dev --extra analysis pytest tests/test_angr_real.py
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from security_scanner.adapters.angr import AngrAdapter, DANGEROUS_SINKS
from security_scanner.models import FunctionSummary, ObservationSeverity, ToolStatus


def _make_func(symbol="suspect_0", start="0x401000", score=0.9):
    return FunctionSummary(
        symbol=symbol,
        start_address=start,
        end_address="0x4010ff",
        triage_score=score,
        reason="test",
        normalized_hash="abc",
    )


# -- Stub/fallback tests (no angr needed) --

def test_angr_disabled():
    result = AngrAdapter().analyze(suspicious_functions=5, enabled=False)
    assert result.observations == []
    assert result.tool_run.status == ToolStatus.UNAVAILABLE


def test_angr_zero_functions():
    result = AngrAdapter().analyze(suspicious_functions=0, enabled=True)
    assert result.tool_run.status == ToolStatus.UNAVAILABLE


def test_angr_stub_when_no_data():
    funcs = [_make_func()]
    result = AngrAdapter().analyze(enabled=True, data=None, functions=funcs)
    assert result.tool_run.details.get("mode") == "stub"
    assert len(result.observations) == 1
    assert result.observations[0].source == "angr-placeholder"


def test_angr_backwards_compatible_count_only():
    result = AngrAdapter().analyze(suspicious_functions=3, enabled=True)
    assert result.tool_run.details.get("mode") == "stub"


# -- Mocked angr tests --

def _make_mock_project(has_sinks=True, found_path=True):
    """Create a mock angr.Project with configurable behavior."""
    project = MagicMock()

    # Mock loader with symbol resolution
    mock_symbol = MagicMock()
    mock_symbol.rebased_addr = 0x500000

    if has_sinks:
        project.loader.find_symbol.side_effect = lambda name: mock_symbol if name == "system" else None
    else:
        project.loader.find_symbol.return_value = None

    project.loader.all_elf_objects = []
    project.loader.all_pe_objects = []

    # Mock state factory
    mock_state = MagicMock()
    project.factory.blank_state.return_value = mock_state

    # Mock simulation manager
    mock_simgr = MagicMock()
    if found_path:
        found_state = MagicMock()
        found_state.addr = 0x500000
        found_state.history.bbl_addrs = [0x401000, 0x401050, 0x500000]
        mock_simgr.found = [found_state]
    else:
        mock_simgr.found = []

    project.factory.simulation_manager.return_value = mock_simgr

    return project


@patch("security_scanner.adapters.angr.HAS_ANGR", True)
def test_angr_finds_dangerous_path():
    adapter = AngrAdapter(timeout_per_function=5, max_states=100, max_functions=4)
    funcs = [_make_func("main", "0x401000", 0.9)]

    mock_project = _make_mock_project(has_sinks=True, found_path=True)

    with patch("security_scanner.adapters.angr._angr") as mock_angr:
        mock_angr.Project.return_value = mock_project
        mock_angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY = "zero_fill_mem"
        mock_angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS = "zero_fill_reg"

        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100, functions=funcs)

    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "angr"
    assert result.tool_run.details["dangerous"] == 1

    high_obs = [o for o in result.observations if o.severity == ObservationSeverity.HIGH]
    assert len(high_obs) == 1
    assert "system" in high_obs[0].message
    assert high_obs[0].source == "angr"
    assert "confirmed" in high_obs[0].tags


@patch("security_scanner.adapters.angr.HAS_ANGR", True)
def test_angr_clean_when_no_paths_found():
    adapter = AngrAdapter(timeout_per_function=5, max_states=100)
    funcs = [_make_func("clean_func", "0x401000")]

    mock_project = _make_mock_project(has_sinks=True, found_path=False)

    with patch("security_scanner.adapters.angr._angr") as mock_angr:
        mock_angr.Project.return_value = mock_project
        mock_angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY = "zero_fill_mem"
        mock_angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS = "zero_fill_reg"

        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100, functions=funcs)

    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["dangerous"] == 0

    info_obs = [o for o in result.observations if o.category == "symbolic:clean"]
    assert len(info_obs) == 1


@patch("security_scanner.adapters.angr.HAS_ANGR", True)
def test_angr_no_sinks_in_binary():
    adapter = AngrAdapter()
    funcs = [_make_func()]

    mock_project = _make_mock_project(has_sinks=False, found_path=False)

    with patch("security_scanner.adapters.angr._angr") as mock_angr:
        mock_angr.Project.return_value = mock_project
        mock_angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY = "zero_fill_mem"
        mock_angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS = "zero_fill_reg"

        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100, functions=funcs)

    assert result.tool_run.status == ToolStatus.PASS
    # No sinks resolved = exploration finds nothing dangerous
    assert result.tool_run.details["dangerous"] == 0


@patch("security_scanner.adapters.angr.HAS_ANGR", True)
def test_angr_respects_max_functions():
    adapter = AngrAdapter(max_functions=2)
    funcs = [_make_func(f"fn_{i}", f"0x40{i}000", score=0.9 - i * 0.1) for i in range(5)]

    mock_project = _make_mock_project(has_sinks=True, found_path=False)

    with patch("security_scanner.adapters.angr._angr") as mock_angr:
        mock_angr.Project.return_value = mock_project
        mock_angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY = "zero_fill_mem"
        mock_angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS = "zero_fill_reg"

        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100, functions=funcs)

    assert result.tool_run.details["explored"] <= 2


@patch("security_scanner.adapters.angr.HAS_ANGR", True)
def test_angr_load_failure_returns_none_falls_back():
    adapter = AngrAdapter()
    funcs = [_make_func()]

    with patch("security_scanner.adapters.angr._angr") as mock_angr:
        mock_angr.Project.side_effect = Exception("Unsupported binary format")

        result = adapter.analyze(enabled=True, data=b"\x00" * 100, functions=funcs)

    assert result.tool_run.details["mode"] == "stub"
    assert result.observations[0].source == "angr-placeholder"


def test_angr_evidence_structure():
    """Verify the observation evidence contains expected fields."""
    adapter = AngrAdapter(timeout_per_function=5, max_states=100)
    funcs = [_make_func("main", "0x401000")]

    mock_project = _make_mock_project(has_sinks=True, found_path=True)

    with patch("security_scanner.adapters.angr.HAS_ANGR", True), \
         patch("security_scanner.adapters.angr._angr") as mock_angr:
        mock_angr.Project.return_value = mock_project
        mock_angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY = "zero_fill_mem"
        mock_angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS = "zero_fill_reg"

        result = adapter.analyze(enabled=True, data=b"MZ" + b"\x00" * 100, functions=funcs)

    obs = result.observations[0]
    assert "function" in obs.evidence
    assert "reached_sinks" in obs.evidence
    assert "states_explored" in obs.evidence
    assert "path_length" in obs.evidence
    assert obs.evidence["function"] == "main"
