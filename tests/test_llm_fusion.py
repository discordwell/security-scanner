"""Tests for LLM-powered fusion verdict reasoning."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from security_scanner.models import (
    ArtifactFormat,
    ArtifactKind,
    ArtifactRecord,
    BaselineDiff,
    Observation,
    ObservationSeverity,
    ProvenanceSummary,
    VerdictState,
)
from security_scanner.pipeline.fusion import (
    FusionPipeline,
    build_fusion_prompt,
    parse_fusion_response,
)


# -- Helpers --


def _make_artifact(
    observations=None,
    provenance_trusted=False,
    baseline_matched=False,
    baseline_id=None,
    baseline_distance=1.0,
):
    return ArtifactRecord(
        sha256="a" * 64,
        sha1="b" * 40,
        md5="c" * 32,
        filename="test.exe",
        size=4096,
        format=ArtifactFormat.PE,
        kind=ArtifactKind.ROOT,
        storage_path="/tmp/test",
        observations=observations or [],
        provenance=ProvenanceSummary(trusted=provenance_trusted),
        baseline_diff=BaselineDiff(
            matched=baseline_matched,
            baseline_id=baseline_id,
            distance=baseline_distance,
        ),
    )


def _obs(severity, source="test", category="test", message="test observation"):
    return Observation(source=source, category=category, severity=severity, message=message)


def _llm_response(verdict="malicious", confidence=0.9, summary="Test", key_factors=None, dissent=None):
    data = {
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary,
        "key_factors": key_factors or [],
        "dissent": dissent,
    }
    return f"```json\n{json.dumps(data)}\n```"


# -- FusionPipeline.has_llm --


def test_has_llm_false_by_default():
    pipeline = FusionPipeline()
    assert pipeline.has_llm is False


def test_has_llm_true_with_adapter():
    pipeline = FusionPipeline(adapter=AsyncMock())
    assert pipeline.has_llm is True


# -- Rule-based verdict unchanged --


def test_rule_based_malicious_still_works():
    """Existing rule-based fusion logic is not broken."""
    art = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    verdict = FusionPipeline().verdict_for(art, [art])
    assert verdict.state == VerdictState.MALICIOUS


def test_rule_based_clean_still_works():
    art = _make_artifact(provenance_trusted=True, baseline_matched=True, baseline_id="bl1", baseline_distance=0.0)
    verdict = FusionPipeline().verdict_for(art, [art])
    assert verdict.state == VerdictState.CLEAN


# -- build_fusion_prompt --


def test_prompt_contains_all_signal_sources():
    art = _make_artifact(
        observations=[
            _obs(ObservationSeverity.HIGH, source="yara", message="YARA match"),
            _obs(ObservationSeverity.MEDIUM, source="ember", message="EMBER score 0.8"),
            _obs(ObservationSeverity.HIGH, source="capa", message="Process injection"),
        ],
        provenance_trusted=True,
    )
    rule_verdict = FusionPipeline().verdict_for(art, [art])
    prompt = build_fusion_prompt(rule_verdict, art, [art])

    assert "yara" in prompt
    assert "ember" in prompt
    assert "capa" in prompt
    assert "MALICIOUS" in prompt or "malicious" in prompt
    assert "Trusted: True" in prompt
    assert art.sha256 in prompt


def test_prompt_contains_baseline_info():
    art = _make_artifact(baseline_matched=True, baseline_id="bl1", baseline_distance=0.1)
    rule_verdict = FusionPipeline().verdict_for(art, [art])
    prompt = build_fusion_prompt(rule_verdict, art, [art])
    assert "Matched: True" in prompt
    assert "0.10" in prompt


# -- parse_fusion_response --


def test_parse_confirms_verdict():
    art = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    rule_verdict = FusionPipeline().verdict_for(art, [art])
    response = _llm_response(verdict="malicious", confidence=0.95, summary="Confirmed malicious")
    result = parse_fusion_response(response, rule_verdict)
    assert result.state == VerdictState.MALICIOUS
    assert any("confirmed" in r.lower() for r in result.reasons)
    # LLM fusion observation added
    fusion_obs = [o for o in result.observations if o.source == "llm-fusion"]
    assert len(fusion_obs) == 1


def test_parse_downgrades_verdict():
    """LLM can downgrade MALICIOUS to SUSPICIOUS with reasoning."""
    art = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    rule_verdict = FusionPipeline().verdict_for(art, [art])
    assert rule_verdict.state == VerdictState.MALICIOUS

    response = _llm_response(
        verdict="suspicious",
        confidence=0.85,
        summary="Single heuristic match with trusted provenance",
        dissent="The HIGH observation is from a heuristic fallback, not a real YARA rule",
    )
    result = parse_fusion_response(response, rule_verdict)
    assert result.state == VerdictState.SUSPICIOUS
    assert any("override" in r.lower() for r in result.reasons)
    fusion_obs = [o for o in result.observations if o.source == "llm-fusion"]
    assert fusion_obs[0].evidence["overridden"] is True


def test_parse_upgrades_verdict():
    """LLM can upgrade SUSPICIOUS to MALICIOUS (kill chain detection)."""
    art = _make_artifact(observations=[
        _obs(ObservationSeverity.MEDIUM, source="yara", message="Script exec"),
        _obs(ObservationSeverity.MEDIUM, source="capa", message="Network"),
    ])
    rule_verdict = FusionPipeline().verdict_for(art, [art])
    assert rule_verdict.state == VerdictState.SUSPICIOUS

    response = _llm_response(
        verdict="malicious",
        confidence=0.88,
        summary="Multiple MEDIUM findings form a coherent kill chain",
        dissent="Script execution + network exfiltration pattern",
    )
    result = parse_fusion_response(response, rule_verdict)
    assert result.state == VerdictState.MALICIOUS


def test_parse_preserves_rule_verdict_in_evidence():
    art = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    rule_verdict = FusionPipeline().verdict_for(art, [art])
    response = _llm_response(verdict="suspicious")
    result = parse_fusion_response(response, rule_verdict)
    fusion_obs = [o for o in result.observations if o.source == "llm-fusion"]
    assert fusion_obs[0].evidence["rule_verdict"] == "malicious"
    assert fusion_obs[0].evidence["llm_verdict"] == "suspicious"


def test_parse_no_json_block_falls_back():
    art = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    rule_verdict = FusionPipeline().verdict_for(art, [art])
    result = parse_fusion_response("No JSON here", rule_verdict)
    assert result.state == VerdictState.MALICIOUS  # unchanged


def test_parse_invalid_json_falls_back():
    art = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    rule_verdict = FusionPipeline().verdict_for(art, [art])
    result = parse_fusion_response("```json\n{bad}\n```", rule_verdict)
    assert result.state == VerdictState.MALICIOUS


def test_parse_unknown_verdict_falls_back():
    art = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    rule_verdict = FusionPipeline().verdict_for(art, [art])
    result = parse_fusion_response(_llm_response(verdict="unknown_state"), rule_verdict)
    assert result.state == VerdictState.MALICIOUS


def test_parse_non_numeric_confidence():
    art = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    rule_verdict = FusionPipeline().verdict_for(art, [art])
    response = '```json\n{"verdict": "malicious", "confidence": "very high", "summary": "test"}\n```'
    result = parse_fusion_response(response, rule_verdict)
    fusion_obs = [o for o in result.observations if o.source == "llm-fusion"]
    assert fusion_obs[0].evidence["confidence"] == 0.5


# -- Async verdict_for_with_llm --


@pytest.mark.asyncio
async def test_verdict_with_llm_calls_adapter():
    mock_adapter = AsyncMock()
    mock_adapter.analyze_file = AsyncMock(
        return_value=(_llm_response(verdict="malicious", confidence=0.95), 1000, 500)
    )
    pipeline = FusionPipeline(adapter=mock_adapter, llm_budget=30_000)

    art = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    verdict = await pipeline.verdict_for_with_llm(art, [art])

    mock_adapter.analyze_file.assert_awaited_once()
    assert verdict.state == VerdictState.MALICIOUS
    assert any(o.source == "llm-fusion" for o in verdict.observations)


@pytest.mark.asyncio
async def test_verdict_with_llm_empty_response_falls_back():
    mock_adapter = AsyncMock()
    mock_adapter.analyze_file = AsyncMock(return_value=("", 0, 0))
    pipeline = FusionPipeline(adapter=mock_adapter)

    art = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    verdict = await pipeline.verdict_for_with_llm(art, [art])

    assert verdict.state == VerdictState.MALICIOUS
    # No llm-fusion observation added
    assert not any(o.source == "llm-fusion" for o in verdict.observations)


@pytest.mark.asyncio
async def test_verdict_without_adapter_returns_rule_based():
    pipeline = FusionPipeline()
    art = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    verdict = await pipeline.verdict_for_with_llm(art, [art])
    assert verdict.state == VerdictState.MALICIOUS
    assert not any(o.source == "llm-fusion" for o in verdict.observations)
