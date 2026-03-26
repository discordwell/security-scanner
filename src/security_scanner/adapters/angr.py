from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from ..models import FunctionSummary, Observation, ObservationSeverity, ToolExecution, ToolStatus
from .types import AdapterResult

logger = logging.getLogger(__name__)

try:
    import angr as _angr
    import claripy as _claripy

    HAS_ANGR = True
except ImportError:
    _angr = None  # type: ignore[assignment]
    _claripy = None  # type: ignore[assignment]
    HAS_ANGR = False

# Dangerous sinks we look for reachable paths to
DANGEROUS_SINKS = {
    # Windows
    "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
    "WriteProcessMemory", "NtWriteVirtualMemory",
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    "system", "_system",
    # POSIX
    "execve", "execvp", "popen", "dlopen",
    "connect", "send", "sendto",
    "mprotect",
}


class AngrAdapter:
    def __init__(
        self,
        timeout_per_function: int = 60,
        max_states: int = 256,
        max_functions: int = 8,
    ) -> None:
        self._timeout = timeout_per_function
        self._max_states = max_states
        self._max_functions = max_functions

    def analyze(
        self,
        suspicious_functions: int | None = None,
        enabled: bool = False,
        data: bytes | None = None,
        functions: list[FunctionSummary] | None = None,
    ) -> AdapterResult:
        # Backwards-compatible: accept old-style call with just count
        if functions is None:
            functions = []
        if suspicious_functions is None:
            suspicious_functions = len(functions)

        if not enabled or suspicious_functions == 0:
            return AdapterResult(
                tool_run=ToolExecution(
                    tool="angr",
                    status=ToolStatus.UNAVAILABLE,
                    summary="Targeted symbolic execution skipped.",
                    details={"enabled": enabled, "suspicious_functions": suspicious_functions},
                )
            )

        if HAS_ANGR and data is not None:
            result = self._analyze_with_angr(data, functions)
            if result is not None:
                return result

        return self._fallback_stub(suspicious_functions)

    def _analyze_with_angr(
        self, data: bytes, functions: list[FunctionSummary],
    ) -> AdapterResult | None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(data)

        try:
            project = _angr.Project(tmp_path, auto_detect_format_string=False, load_options={"auto_load_libs": False})
        except Exception as exc:
            logger.warning("angr failed to load binary: %s", exc)
            tmp_path.unlink(missing_ok=True)
            return None

        observations: list[Observation] = []
        targets = sorted(functions, key=lambda f: f.triage_score, reverse=True)[: self._max_functions]
        explored_count = 0
        dangerous_count = 0

        # Resolve which dangerous sinks exist in the binary's symbol table
        resolved_sinks: dict[str, int] = {}
        for sink_name in DANGEROUS_SINKS:
            sym = project.loader.find_symbol(sink_name)
            if sym is not None:
                resolved_sinks[sink_name] = sym.rebased_addr

        if not resolved_sinks:
            logger.info("angr: no dangerous sinks found in symbol table, trying PLT")
            for obj in project.loader.all_elf_objects:
                if hasattr(obj, "plt"):
                    for name, addr in obj.plt.items():
                        if name in DANGEROUS_SINKS:
                            resolved_sinks[name] = addr
            # Also check PE imports
            for obj in project.loader.all_pe_objects:
                if hasattr(obj, "imports"):
                    for imp_name in obj.imports:
                        if imp_name in DANGEROUS_SINKS:
                            sym = project.loader.find_symbol(imp_name)
                            if sym:
                                resolved_sinks[imp_name] = sym.rebased_addr

        sink_addrs = set(resolved_sinks.values())

        for func_summary in targets:
            try:
                start_addr = int(func_summary.start_address, 16)
            except (ValueError, TypeError):
                continue

            try:
                result = self._explore_function(project, start_addr, sink_addrs)
                explored_count += 1
            except Exception as exc:
                logger.warning("angr: exploration failed for %s: %s", func_summary.symbol, exc)
                continue

            if result:
                dangerous_count += 1
                reached_sinks = result["reached_sinks"]
                sink_names = [
                    name for name, addr in resolved_sinks.items() if addr in reached_sinks
                ]
                observations.append(
                    Observation(
                        source="angr",
                        category="symbolic:reachable_sink",
                        severity=ObservationSeverity.HIGH,
                        message=f"Symbolic execution confirmed reachable path from {func_summary.symbol} to dangerous call(s): {', '.join(sink_names)}.",
                        evidence={
                            "function": func_summary.symbol,
                            "start_address": func_summary.start_address,
                            "reached_sinks": sink_names,
                            "states_explored": result["states_explored"],
                            "path_length": result["path_length"],
                        },
                        addresses=[func_summary.start_address] + [hex(a) for a in reached_sinks],
                        tags=["symbolic", "confirmed", *sink_names],
                    )
                )

        if explored_count > 0 and dangerous_count == 0:
            observations.append(
                Observation(
                    source="angr",
                    category="symbolic:clean",
                    severity=ObservationSeverity.INFO,
                    message=f"Symbolic execution explored {explored_count} functions with no confirmed dangerous paths.",
                    evidence={"explored": explored_count},
                    tags=["symbolic"],
                )
            )

        tool_run = ToolExecution(
            tool="angr",
            status=ToolStatus.PASS,
            summary=f"angr explored {explored_count} functions, found {dangerous_count} with reachable dangerous sinks.",
            details={
                "mode": "angr",
                "explored": explored_count,
                "dangerous": dangerous_count,
                "sinks_available": list(resolved_sinks.keys()),
                "timeout_per_function": self._timeout,
                "max_states": self._max_states,
            },
        )
        logger.info("angr: explored=%d dangerous=%d sinks=%d", explored_count, dangerous_count, len(resolved_sinks))

        tmp_path.unlink(missing_ok=True)
        return AdapterResult(observations=observations, tool_run=tool_run)

    def _explore_function(
        self, project, start_addr: int, sink_addrs: set[int],
    ) -> dict | None:
        if not sink_addrs:
            return None

        state = project.factory.blank_state(
            addr=start_addr,
            add_options={
                _angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                _angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )

        simgr = project.factory.simulation_manager(state)

        states_explored = 0

        def step_callback(sm):
            nonlocal states_explored
            states_explored += len(sm.active)

        try:
            simgr.explore(
                find=sink_addrs,
                num_find=1,
                timeout=self._timeout,
                step_func=step_callback,
            )
        except Exception as exc:
            logger.debug("angr exploration exception for 0x%x: %s", start_addr, exc)
            return None

        # Also cap by total states seen
        if states_explored > self._max_states and not simgr.found:
            return None

        if simgr.found:
            found_state = simgr.found[0]
            reached_addr = found_state.addr
            path_length = len(found_state.history.bbl_addrs)
            return {
                "reached_sinks": {reached_addr},
                "states_explored": states_explored,
                "path_length": path_length,
            }

        return None

    def _fallback_stub(self, suspicious_functions: int) -> AdapterResult:
        observation = Observation(
            source="angr-placeholder",
            category="symbolic_execution",
            severity=ObservationSeverity.INFO,
            message="Suspicious regions were queued for targeted symbolic execution, but no external angr runner is configured in local mode.",
            evidence={"suspicious_functions": suspicious_functions},
            tags=["symbolic"],
        )
        return AdapterResult(
            observations=[observation],
            tool_run=ToolExecution(
                tool="angr",
                status=ToolStatus.UNAVAILABLE,
                summary="Targeted symbolic execution was requested but no backend is configured.",
                details={"queued_regions": suspicious_functions, "mode": "stub"},
            ),
        )
