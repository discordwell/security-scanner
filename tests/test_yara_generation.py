"""Tests for auto YARA rule generation from malicious samples."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from security_scanner.models import (
    ArtifactFormat,
    ArtifactKind,
    ArtifactRecord,
    FunctionSummary,
    Observation,
    ObservationSeverity,
    ProvenanceSummary,
    BaselineDiff,
    VerdictRecord,
    VerdictState,
)
from security_scanner.pipeline.yara_generation import (
    YaraGenerationPipeline,
    build_yara_gen_prompt,
    parse_yara_rules,
)


# -- Helpers --


SAMPLE_YARA_RULE = """\
rule Mal_Injector_VirtualAlloc {
    meta:
        author = "auto-generated"
        description = "Detects process injector using VirtualAlloc"
        date = "2026-04-05"
        severity = "high"

    strings:
        $api1 = "VirtualAlloc"
        $api2 = "CreateRemoteThread"
        $c2 = { 68 74 74 70 73 3A 2F 2F }

    condition:
        all of ($api*) and $c2
}"""


def _llm_response_with_rules(*rules: str) -> str:
    blocks = "\n\n".join(f"```yara\n{r}\n```" for r in rules)
    return f"Generated YARA rules:\n\n{blocks}"


def _make_artifact(strings=None):
    return ArtifactRecord(
        sha256="a" * 64,
        sha1="b" * 40,
        md5="c" * 32,
        filename="malware.exe",
        size=4096,
        format=ArtifactFormat.PE,
        kind=ArtifactKind.ROOT,
        storage_path="/tmp/test",
        strings=strings or ["CreateRemoteThread", "VirtualAlloc", "https://evil.example"],
        provenance=ProvenanceSummary(),
        baseline_diff=BaselineDiff(),
    )


def _make_verdict(state=VerdictState.MALICIOUS, observations=None, functions=None, confidence=0.95):
    obs = observations or [
        Observation(
            source="yara",
            category="rule:process_injection",
            severity=ObservationSeverity.HIGH,
            message="YARA match: process injection",
        ),
        Observation(
            source="llm-fusion",
            category="llm:verdict",
            severity=ObservationSeverity.INFO,
            message="LLM fusion: malicious",
            evidence={"confidence": confidence, "llm_verdict": "malicious"},
        ),
    ]
    return VerdictRecord(
        sha256="a" * 64,
        state=state,
        summary="Malicious",
        reasons=["test"],
        observations=obs,
        functions=functions or [],
    )


# -- parse_yara_rules --


def test_parse_single_valid_rule():
    response = _llm_response_with_rules(SAMPLE_YARA_RULE)
    rules = parse_yara_rules(response)
    assert len(rules) == 1
    assert rules[0][0] == "Mal_Injector_VirtualAlloc"
    assert "VirtualAlloc" in rules[0][1]


def test_parse_multiple_rules():
    rule2 = 'rule Mal_C2_Beacon {\n    strings:\n        $s1 = "beacon"\n    condition:\n        $s1\n}'
    response = _llm_response_with_rules(SAMPLE_YARA_RULE, rule2)
    rules = parse_yara_rules(response)
    assert len(rules) == 2
    names = [r[0] for r in rules]
    assert "Mal_Injector_VirtualAlloc" in names
    assert "Mal_C2_Beacon" in names


def test_parse_rule_missing_condition():
    bad_rule = 'rule Bad {\n    strings:\n        $s1 = "test"\n}'
    response = _llm_response_with_rules(bad_rule)
    rules = parse_yara_rules(response)
    assert len(rules) == 0


def test_parse_no_rules():
    rules = parse_yara_rules("No YARA rules here")
    assert rules == []


def test_parse_rule_without_name():
    bad_rule = '{\n    strings:\n        $s1 = "test"\n    condition:\n        $s1\n}'
    response = f"```yara\n{bad_rule}\n```"
    rules = parse_yara_rules(response)
    assert len(rules) == 0


# -- build_yara_gen_prompt --


def test_prompt_contains_artifact_info():
    artifact = _make_artifact()
    verdict = _make_verdict()
    prompt = build_yara_gen_prompt(artifact, verdict)
    assert artifact.sha256 in prompt
    assert "malware.exe" in prompt
    assert "pe" in prompt.lower()
    assert "CreateRemoteThread" in prompt


def test_prompt_contains_observations():
    artifact = _make_artifact()
    verdict = _make_verdict()
    prompt = build_yara_gen_prompt(artifact, verdict)
    assert "process injection" in prompt
    assert "yara" in prompt


def test_prompt_contains_decompiled_functions():
    artifact = _make_artifact()
    func = FunctionSummary(
        symbol="inject_shellcode",
        start_address="0x401000",
        end_address="0x4010ff",
        triage_score=0.9,
        reason="Process injection",
        normalized_hash="abc",
        decompiled=True,
        decompiled_code="void inject_shellcode() { VirtualAlloc(0, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE); }",
    )
    verdict = _make_verdict(functions=[func])
    prompt = build_yara_gen_prompt(artifact, verdict)
    assert "inject_shellcode" in prompt
    assert "VirtualAlloc" in prompt


# -- YaraGenerationPipeline --


@pytest.fixture()
def mock_adapter():
    adapter = AsyncMock()
    adapter.analyze_file = AsyncMock(
        return_value=(_llm_response_with_rules(SAMPLE_YARA_RULE), 800, 400)
    )
    return adapter


@pytest.mark.asyncio
async def test_pipeline_generates_rules(mock_adapter, tmp_path):
    rules_dir = tmp_path / "auto_rules"
    pipeline = YaraGenerationPipeline(
        adapter=mock_adapter, rules_dir=rules_dir, budget=20_000
    )
    artifact = _make_artifact()
    verdict = _make_verdict()

    rule_names = await pipeline.generate(artifact, verdict)

    assert len(rule_names) == 1
    assert "Mal_Injector_VirtualAlloc" in rule_names
    rule_file = rules_dir / f"{artifact.sha256[:12]}.yar"
    assert rule_file.exists()
    assert "VirtualAlloc" in rule_file.read_text()


@pytest.mark.asyncio
async def test_pipeline_skips_non_malicious(mock_adapter, tmp_path):
    pipeline = YaraGenerationPipeline(
        adapter=mock_adapter, rules_dir=tmp_path / "rules"
    )
    artifact = _make_artifact()
    verdict = _make_verdict(state=VerdictState.SUSPICIOUS)

    rule_names = await pipeline.generate(artifact, verdict)
    assert rule_names == []
    mock_adapter.analyze_file.assert_not_awaited()


@pytest.mark.asyncio
async def test_pipeline_skips_low_confidence(mock_adapter, tmp_path):
    pipeline = YaraGenerationPipeline(
        adapter=mock_adapter, rules_dir=tmp_path / "rules", min_confidence=0.8
    )
    artifact = _make_artifact()
    verdict = _make_verdict(confidence=0.5)

    rule_names = await pipeline.generate(artifact, verdict)
    assert rule_names == []
    mock_adapter.analyze_file.assert_not_awaited()


@pytest.mark.asyncio
async def test_pipeline_handles_empty_response(mock_adapter, tmp_path):
    mock_adapter.analyze_file = AsyncMock(return_value=("", 0, 0))
    pipeline = YaraGenerationPipeline(
        adapter=mock_adapter, rules_dir=tmp_path / "rules"
    )
    artifact = _make_artifact()
    verdict = _make_verdict()

    rule_names = await pipeline.generate(artifact, verdict)
    assert rule_names == []


@pytest.mark.asyncio
async def test_pipeline_handles_invalid_rules(mock_adapter, tmp_path):
    bad = 'rule Bad {\n    strings:\n        $s = "x"\n}'  # no condition
    mock_adapter.analyze_file = AsyncMock(
        return_value=(_llm_response_with_rules(bad), 500, 300)
    )
    pipeline = YaraGenerationPipeline(
        adapter=mock_adapter, rules_dir=tmp_path / "rules"
    )
    artifact = _make_artifact()
    verdict = _make_verdict()

    rule_names = await pipeline.generate(artifact, verdict)
    assert rule_names == []


@pytest.mark.asyncio
async def test_pipeline_no_fusion_obs_still_generates(mock_adapter, tmp_path):
    """Without LLM fusion observations, skip confidence check and generate."""
    pipeline = YaraGenerationPipeline(
        adapter=mock_adapter, rules_dir=tmp_path / "rules"
    )
    artifact = _make_artifact()
    verdict = _make_verdict(observations=[
        Observation(source="yara", category="test", severity=ObservationSeverity.HIGH, message="test"),
    ])

    rule_names = await pipeline.generate(artifact, verdict)
    assert len(rule_names) == 1
