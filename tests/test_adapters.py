from __future__ import annotations

from security_scanner.adapters.angr import AngrAdapter
from security_scanner.adapters.capa import CapaAdapter
from security_scanner.adapters.cape import CapeAdapter
from security_scanner.adapters.drakvuf import DrakvufAdapter
from security_scanner.adapters.ghidra import GhidraAdapter
from security_scanner.adapters.provenance import ProvenanceAdapter
from security_scanner.adapters.yara import YaraAdapter
from security_scanner.models import ProvenanceBundle, ToolStatus


# -- YaraAdapter --

def test_yara_adapter_detects_suspicious_strings(malicious_pe_bytes):
    result = YaraAdapter().analyze(malicious_pe_bytes)
    assert len(result.observations) > 0
    assert all(obs.source == "yara-heuristic" for obs in result.observations)
    assert result.tool_run.status == ToolStatus.PASS


def test_yara_adapter_benign_returns_no_observations():
    data = b"\x00" * 256
    result = YaraAdapter().analyze(data)
    assert result.observations == []
    assert result.tool_run.status == ToolStatus.PASS


# -- CapaAdapter --

def test_capa_adapter_detects_injection_capability():
    strings = ["CreateRemoteThread", "WriteProcessMemory", "VirtualAlloc"]
    result = CapaAdapter().analyze(strings)
    categories = [obs.category for obs in result.observations]
    assert "capability:process_injection" in categories
    assert "capability:memory_exec" in categories
    assert result.tool_run.status == ToolStatus.PASS


def test_capa_adapter_benign_returns_no_observations():
    strings = ["normal", "application", "strings"]
    result = CapaAdapter().analyze(strings)
    assert result.observations == []
    assert result.tool_run.status == ToolStatus.PASS


def test_capa_adapter_partial_match_not_triggered():
    strings = ["CreateRemoteThread"]
    result = CapaAdapter().analyze(strings)
    categories = [obs.category for obs in result.observations]
    assert "capability:process_injection" not in categories


# -- GhidraAdapter --

def test_ghidra_adapter_promotes_functions(malicious_pe_bytes):
    result = GhidraAdapter().analyze(malicious_pe_bytes, deep_limit=8)
    assert len(result.functions) > 0
    assert len(result.observations) > 0
    assert all(f.symbol.startswith("suspect_region_") for f in result.functions)
    assert result.tool_run.status == ToolStatus.PASS


def test_ghidra_adapter_zero_limit_returns_empty(malicious_pe_bytes):
    result = GhidraAdapter().analyze(malicious_pe_bytes, deep_limit=0)
    assert result.functions == []
    assert result.observations == []


def test_ghidra_adapter_benign_no_functions():
    data = b"\x00" * 256
    result = GhidraAdapter().analyze(data, deep_limit=8)
    assert result.functions == []


def test_ghidra_adapter_triage_scores_decrease():
    data = b"CreateRemoteThread\x00WriteProcessMemory\x00VirtualAlloc"
    result = GhidraAdapter().analyze(data, deep_limit=8)
    if len(result.functions) >= 2:
        scores = [f.triage_score for f in result.functions]
        assert scores == sorted(scores, reverse=True)


# -- ProvenanceAdapter --

def test_provenance_adapter_trusted_when_authenticode_set():
    bundle = ProvenanceBundle(claimed_signer="Microsoft", authenticode_trusted=True)
    summary, tool = ProvenanceAdapter().analyze(bundle)
    assert summary.trusted is True
    assert summary.authenticode_status == "trusted"
    assert tool.status == ToolStatus.PASS


def test_provenance_adapter_trusted_when_sigstore_set():
    bundle = ProvenanceBundle(sigstore_subject="subject@example.com")
    summary, tool = ProvenanceAdapter().analyze(bundle)
    assert summary.trusted is True
    assert summary.sigstore_status == "present"


def test_provenance_adapter_untrusted_when_no_provenance():
    bundle = ProvenanceBundle()
    summary, tool = ProvenanceAdapter().analyze(bundle)
    assert summary.trusted is False
    assert tool.status == ToolStatus.UNAVAILABLE


def test_provenance_adapter_trusted_when_in_toto_set():
    bundle = ProvenanceBundle(in_toto_layout="layout.json")
    summary, tool = ProvenanceAdapter().analyze(bundle)
    assert summary.trusted is True
    assert summary.in_toto_status == "present"


# -- AngrAdapter --

def test_angr_adapter_disabled():
    result = AngrAdapter().analyze(suspicious_functions=5, enabled=False)
    assert result.observations == []
    assert result.tool_run.status == ToolStatus.UNAVAILABLE


def test_angr_adapter_enabled_no_functions():
    result = AngrAdapter().analyze(suspicious_functions=0, enabled=True)
    assert result.observations == []
    assert result.tool_run.status == ToolStatus.UNAVAILABLE


def test_angr_adapter_enabled_with_functions():
    result = AngrAdapter().analyze(suspicious_functions=3, enabled=True)
    assert len(result.observations) == 1
    assert result.observations[0].source == "angr-placeholder"
    assert result.tool_run.status == ToolStatus.UNAVAILABLE


# -- CapeAdapter --

def test_cape_adapter_disabled():
    result = CapeAdapter().analyze(enabled=False)
    assert result.behavior == []
    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.tool_run.details.get("enabled") is False


def test_cape_adapter_enabled_stub():
    result = CapeAdapter().analyze(enabled=True)
    assert len(result.behavior) == 1
    assert result.behavior[0].source == "cape-placeholder"
    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.tool_run.details.get("enabled") is True


# -- DrakvufAdapter --

def test_drakvuf_adapter_disabled():
    result = DrakvufAdapter().analyze(enabled=False)
    assert result.behavior == []
    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.tool_run.details.get("enabled") is False


def test_drakvuf_adapter_enabled_stub():
    result = DrakvufAdapter().analyze(enabled=True)
    assert len(result.behavior) == 1
    assert result.behavior[0].source == "drakvuf-placeholder"
    assert result.tool_run.status == ToolStatus.UNAVAILABLE
    assert result.tool_run.details.get("enabled") is True
