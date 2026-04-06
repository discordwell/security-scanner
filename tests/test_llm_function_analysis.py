"""Tests for LLM-powered decompiled function analysis pipeline."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_scanner.models import (
    ArtifactFormat,
    ArtifactRecord,
    FunctionSummary,
    ObservationSeverity,
    ToolStatus,
)
from security_scanner.pipeline.llm_function_analysis import (
    LLMFunctionAnalysisPipeline,
    build_function_prompt,
    parse_function_response,
    select_functions,
)


# -- Helpers --


def _make_function(
    symbol: str = "FUN_00401000",
    triage_score: float = 0.8,
    decompiled_code: str | None = "void FUN_00401000(void) { return; }",
) -> FunctionSummary:
    return FunctionSummary(
        symbol=symbol,
        start_address="0x00401000",
        end_address="0x004010ff",
        triage_score=triage_score,
        reason="Ghidra function",
        normalized_hash="abc123",
        decompiled=decompiled_code is not None,
        decompiled_code=decompiled_code,
        evidence={"size": 256, "calling": ["memcpy", "VirtualAlloc"], "called_by": ["main"]},
    )


def _make_artifact(functions: list[FunctionSummary] | None = None) -> ArtifactRecord:
    return ArtifactRecord(
        sha256="a" * 64,
        sha1="b" * 40,
        md5="c" * 32,
        filename="sample.exe",
        size=4096,
        format=ArtifactFormat.PE,
        kind="root",
        storage_path="/tmp/test",
        strings=["CreateRemoteThread", "https://evil.example"],
        functions=functions or [],
    )


_SENTINEL = object()


def _make_llm_response(
    verdict: str = "malicious",
    confidence: float = 0.9,
    summary: str = "Shellcode loader",
    behaviors: list[str] | None = None,
    findings: list[dict] | object = _SENTINEL,
) -> str:
    default_findings = [
        {"severity": "high", "category": "process_injection", "message": "Allocates executable memory and copies shellcode"}
    ]
    data = {
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary,
        "behaviors": behaviors or ["process_injection"],
        "findings": default_findings if findings is _SENTINEL else findings,
    }
    return f"Analysis:\n```json\n{json.dumps(data, indent=2)}\n```"


# -- select_functions --


def test_select_functions_filters_by_triage_score():
    funcs = [
        _make_function(symbol="low", triage_score=0.3),
        _make_function(symbol="high", triage_score=0.9),
        _make_function(symbol="mid", triage_score=0.6),
    ]
    selected = select_functions(funcs, min_triage_score=0.5, max_functions=10, max_code_length=10_000)
    symbols = [f.symbol for f in selected]
    assert "low" not in symbols
    assert symbols == ["high", "mid"]  # sorted by score desc


def test_select_functions_requires_decompiled_code():
    funcs = [
        _make_function(symbol="has_code", decompiled_code="void f() {}"),
        _make_function(symbol="no_code", decompiled_code=None),
    ]
    selected = select_functions(funcs, min_triage_score=0.0, max_functions=10, max_code_length=10_000)
    assert len(selected) == 1
    assert selected[0].symbol == "has_code"


def test_select_functions_respects_max():
    funcs = [_make_function(symbol=f"f{i}", triage_score=0.9 - i * 0.01) for i in range(10)]
    selected = select_functions(funcs, min_triage_score=0.0, max_functions=3, max_code_length=10_000)
    assert len(selected) == 3


def test_select_functions_filters_long_code():
    funcs = [
        _make_function(symbol="short", decompiled_code="void f() {}"),
        _make_function(symbol="long", decompiled_code="x" * 20_000),
    ]
    selected = select_functions(funcs, min_triage_score=0.0, max_functions=10, max_code_length=10_000)
    assert len(selected) == 1
    assert selected[0].symbol == "short"


def test_select_functions_empty_list():
    selected = select_functions([], min_triage_score=0.5, max_functions=5, max_code_length=10_000)
    assert selected == []


# -- build_function_prompt --


def test_prompt_contains_function_code():
    func = _make_function(decompiled_code="int main() { system(\"/bin/sh\"); }")
    artifact = _make_artifact([func])
    prompt = build_function_prompt(func, artifact)
    assert "int main() { system(\"/bin/sh\"); }" in prompt
    assert func.symbol in prompt
    assert func.start_address in prompt


def test_prompt_includes_binary_context():
    func = _make_function()
    artifact = _make_artifact([func])
    prompt = build_function_prompt(func, artifact)
    assert "pe" in prompt.lower()
    assert artifact.sha256 in prompt
    assert "CreateRemoteThread" in prompt


def test_prompt_includes_call_graph():
    func = _make_function()
    artifact = _make_artifact([func])
    prompt = build_function_prompt(func, artifact)
    assert "memcpy" in prompt
    assert "VirtualAlloc" in prompt
    assert "main" in prompt


# -- parse_function_response --


def test_parse_malicious_response():
    func = _make_function()
    response = _make_llm_response(verdict="malicious", confidence=0.95)
    observations = parse_function_response(response, func)
    assert len(observations) >= 1
    verdict_obs = observations[0]
    assert verdict_obs.source == "llm-function"
    assert verdict_obs.severity == ObservationSeverity.HIGH
    assert verdict_obs.evidence["verdict"] == "malicious"
    assert verdict_obs.evidence["confidence"] == 0.95


def test_parse_suspicious_response():
    func = _make_function()
    response = _make_llm_response(verdict="suspicious", confidence=0.6)
    observations = parse_function_response(response, func)
    verdict_obs = observations[0]
    assert verdict_obs.severity == ObservationSeverity.MEDIUM
    assert verdict_obs.category == "llm:function_suspicious"


def test_parse_benign_response():
    func = _make_function()
    response = _make_llm_response(verdict="benign", confidence=0.95, summary="Normal init")
    observations = parse_function_response(response, func)
    verdict_obs = observations[0]
    assert verdict_obs.severity == ObservationSeverity.INFO
    assert "benign" in verdict_obs.tags


def test_parse_malicious_low_confidence_produces_medium():
    """Malicious verdict below 0.7 confidence should produce MEDIUM, not HIGH."""
    func = _make_function()
    response = _make_llm_response(verdict="malicious", confidence=0.4, findings=[])
    observations = parse_function_response(response, func)
    assert len(observations) == 1
    assert observations[0].severity == ObservationSeverity.MEDIUM
    assert observations[0].category == "llm:function_suspicious"
    assert "low confidence" in observations[0].message


def test_parse_findings_extracted():
    func = _make_function()
    findings = [
        {"severity": "high", "category": "c2", "message": "Beaconing to hardcoded IP"},
        {"severity": "medium", "category": "evasion", "message": "Anti-debug check"},
    ]
    response = _make_llm_response(findings=findings)
    observations = parse_function_response(response, func)
    categories = [o.category for o in observations]
    assert "llm:c2" in categories
    assert "llm:evasion" in categories


def test_parse_benign_high_triage_flagged_for_review():
    """Benign verdict on a high-triage function should flag for manual review."""
    func = _make_function(triage_score=0.9)
    response = _make_llm_response(verdict="benign", confidence=0.95, summary="Normal init")
    observations = parse_function_response(response, func)
    assert len(observations) >= 1
    review_obs = observations[0]
    assert review_obs.severity == ObservationSeverity.MEDIUM
    assert "review_needed" in review_obs.tags
    assert "verify manually" in review_obs.message


def test_parse_benign_low_triage_accepted():
    """Benign verdict on a low-triage function is accepted as INFO."""
    func = _make_function(triage_score=0.5)
    response = _make_llm_response(verdict="benign", confidence=0.95, summary="Normal init")
    observations = parse_function_response(response, func)
    assert observations[0].severity == ObservationSeverity.INFO
    assert "benign" in observations[0].tags


def test_parse_non_numeric_confidence_defaults():
    """Non-numeric confidence value should not crash, defaults to 0.5."""
    func = _make_function()
    response = '```json\n{"verdict": "suspicious", "confidence": "high", "summary": "test", "behaviors": [], "findings": []}\n```'
    observations = parse_function_response(response, func)
    assert len(observations) >= 1
    assert observations[0].evidence["confidence"] == 0.5


def test_parse_no_json_block():
    func = _make_function()
    observations = parse_function_response("No JSON here", func)
    assert observations == []


def test_parse_invalid_json():
    func = _make_function()
    observations = parse_function_response("```json\n{invalid}\n```", func)
    assert observations == []


def test_parse_addresses_set():
    func = _make_function()
    response = _make_llm_response()
    observations = parse_function_response(response, func)
    for obs in observations:
        assert func.start_address in obs.addresses


# -- LLMFunctionAnalysisPipeline --


@pytest.fixture()
def mock_llm_adapter():
    """Create a mock AnthropicLLMAdapter."""
    adapter = AsyncMock()
    adapter.analyze_file = AsyncMock(return_value=(_make_llm_response(), 500, 200))
    return adapter


@pytest.mark.asyncio
async def test_pipeline_analyzes_eligible_functions(mock_llm_adapter):
    func = _make_function(triage_score=0.8, decompiled_code="void f() { exec(); }")
    artifact = _make_artifact([func])

    pipeline = LLMFunctionAnalysisPipeline(adapter=mock_llm_adapter, budget=50_000)
    result = await pipeline.analyze(artifact)

    mock_llm_adapter.analyze_file.assert_awaited_once()
    assert len(result.observations) > 0
    assert any(o.source == "llm-function" for o in result.observations)
    tool_run = next(t for t in result.tool_runs if t.tool == "llm-function")
    assert tool_run.status == ToolStatus.PASS
    assert tool_run.details["functions_analyzed"] == 1


@pytest.mark.asyncio
async def test_pipeline_skips_no_eligible_functions(mock_llm_adapter):
    func = _make_function(triage_score=0.1, decompiled_code=None)
    artifact = _make_artifact([func])

    pipeline = LLMFunctionAnalysisPipeline(adapter=mock_llm_adapter, min_triage_score=0.5)
    result = await pipeline.analyze(artifact)

    mock_llm_adapter.analyze_file.assert_not_awaited()
    tool_run = next(t for t in result.tool_runs if t.tool == "llm-function")
    assert tool_run.details["functions_analyzed"] == 0


@pytest.mark.asyncio
async def test_pipeline_respects_budget(mock_llm_adapter):
    """Budget exhausted mid-analysis should stop early."""
    funcs = [_make_function(symbol=f"f{i}", triage_score=0.9 - i * 0.01) for i in range(5)]
    artifact = _make_artifact(funcs)

    # Each call uses 700 tokens; budget of 1500 allows ~2 calls
    pipeline = LLMFunctionAnalysisPipeline(adapter=mock_llm_adapter, budget=1500)
    result = await pipeline.analyze(artifact)

    assert mock_llm_adapter.analyze_file.await_count <= 3


@pytest.mark.asyncio
async def test_pipeline_handles_empty_response(mock_llm_adapter):
    mock_llm_adapter.analyze_file = AsyncMock(return_value=("", 0, 0))
    func = _make_function()
    artifact = _make_artifact([func])

    pipeline = LLMFunctionAnalysisPipeline(adapter=mock_llm_adapter, budget=50_000)
    result = await pipeline.analyze(artifact)

    # No crash, no observations from empty response
    llm_obs = [o for o in result.observations if o.source == "llm-function"]
    assert len(llm_obs) == 0


@pytest.mark.asyncio
async def test_pipeline_empty_artifact(mock_llm_adapter):
    artifact = _make_artifact([])
    pipeline = LLMFunctionAnalysisPipeline(adapter=mock_llm_adapter)
    result = await pipeline.analyze(artifact)
    mock_llm_adapter.analyze_file.assert_not_awaited()


@pytest.mark.asyncio
async def test_pipeline_multiple_functions(mock_llm_adapter):
    """Pipeline processes multiple functions in triage-score order."""
    funcs = [
        _make_function(symbol="low_priority", triage_score=0.6, decompiled_code="void low() {}"),
        _make_function(symbol="high_priority", triage_score=0.9, decompiled_code="void high() {}"),
    ]
    artifact = _make_artifact(funcs)

    pipeline = LLMFunctionAnalysisPipeline(adapter=mock_llm_adapter, budget=50_000, max_functions=2)
    result = await pipeline.analyze(artifact)

    assert mock_llm_adapter.analyze_file.await_count == 2
    # Verify high-priority function was analyzed first (by checking prompt order)
    first_prompt = mock_llm_adapter.analyze_file.call_args_list[0][1].get("prompt", mock_llm_adapter.analyze_file.call_args_list[0][0][0])
    assert "high_priority" in first_prompt
