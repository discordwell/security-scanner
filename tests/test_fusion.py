from __future__ import annotations

from security_scanner.models import (
    ArtifactFormat,
    ArtifactKind,
    ArtifactRecord,
    BaselineDiff,
    Observation,
    ObservationSeverity,
    ProvenanceSummary,
    ToolExecution,
    ToolStatus,
    VerdictState,
)
from security_scanner.pipeline.fusion import FusionPipeline


def _make_artifact(
    observations=None,
    provenance_trusted=False,
    baseline_matched=False,
    baseline_id=None,
    baseline_distance=1.0,
    tool_runs=None,
):
    return ArtifactRecord(
        sha256="abc",
        sha1="a",
        md5="b",
        filename="test.exe",
        size=100,
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
        tool_runs=tool_runs or [],
    )


def _obs(severity, category="test", source="test"):
    return Observation(source=source, category=category, severity=severity, message="test observation")


# -- Verdict states --

def test_clean_verdict_requires_provenance_and_baseline():
    artifact = _make_artifact(
        provenance_trusted=True,
        baseline_matched=True,
        baseline_id="bl-1",
        baseline_distance=0.0,
    )
    verdict = FusionPipeline().verdict_for(artifact, [artifact])
    assert verdict.state == VerdictState.CLEAN


def test_malicious_verdict_on_high_observation():
    artifact = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    verdict = FusionPipeline().verdict_for(artifact, [artifact])
    assert verdict.state == VerdictState.MALICIOUS


def test_malicious_verdict_on_critical_observation():
    artifact = _make_artifact(observations=[_obs(ObservationSeverity.CRITICAL)])
    verdict = FusionPipeline().verdict_for(artifact, [artifact])
    assert verdict.state == VerdictState.MALICIOUS


def test_suspicious_verdict_on_medium_observation():
    artifact = _make_artifact(
        observations=[_obs(ObservationSeverity.MEDIUM)],
        baseline_distance=0.0,
        baseline_id="bl-1",
    )
    verdict = FusionPipeline().verdict_for(artifact, [artifact])
    assert verdict.state == VerdictState.SUSPICIOUS


def test_suspicious_verdict_on_high_baseline_distance():
    artifact = _make_artifact(
        baseline_distance=0.5,
        baseline_id="bl-1",
        baseline_matched=False,
    )
    verdict = FusionPipeline().verdict_for(artifact, [artifact])
    assert verdict.state == VerdictState.SUSPICIOUS


def test_suspicious_overridden_to_clean_with_provenance_and_baseline():
    artifact = _make_artifact(
        observations=[_obs(ObservationSeverity.MEDIUM)],
        provenance_trusted=True,
        baseline_matched=True,
        baseline_id="bl-1",
        baseline_distance=0.1,
    )
    verdict = FusionPipeline().verdict_for(artifact, [artifact])
    assert verdict.state == VerdictState.CLEAN


def test_inconclusive_verdict_no_provenance_no_baseline():
    artifact = _make_artifact(
        provenance_trusted=False,
        baseline_matched=False,
        baseline_id=None,
    )
    verdict = FusionPipeline().verdict_for(artifact, [artifact])
    assert verdict.state == VerdictState.INCONCLUSIVE


# -- Pending actions --

def test_coverage_gap_adds_pending_action():
    artifact = _make_artifact(
        observations=[_obs(ObservationSeverity.INFO, category="coverage_gap")],
        provenance_trusted=True,
        baseline_matched=True,
        baseline_id="bl-1",
        baseline_distance=0.0,
    )
    verdict = FusionPipeline().verdict_for(artifact, [artifact])
    assert any("decompilation" in action for action in verdict.pending_actions)


def test_dynamic_gap_adds_pending_action():
    tool_run = ToolExecution(
        tool="cape",
        status=ToolStatus.UNAVAILABLE,
        summary="No backend",
        details={"enabled": True},
    )
    artifact = _make_artifact(
        provenance_trusted=True,
        baseline_matched=True,
        baseline_id="bl-1",
        baseline_distance=0.0,
        tool_runs=[tool_run],
    )
    verdict = FusionPipeline().verdict_for(artifact, [artifact])
    assert any("CAPE" in action or "DRAKVUF" in action for action in verdict.pending_actions)


def test_no_baseline_id_adds_register_action():
    artifact = _make_artifact(baseline_id=None)
    verdict = FusionPipeline().verdict_for(artifact, [artifact])
    assert any("baseline" in action.lower() for action in verdict.pending_actions)


def test_malicious_suppresses_dynamic_gap_action():
    tool_run = ToolExecution(
        tool="cape",
        status=ToolStatus.UNAVAILABLE,
        summary="No backend",
        details={"enabled": True},
    )
    artifact = _make_artifact(
        observations=[_obs(ObservationSeverity.HIGH)],
        tool_runs=[tool_run],
    )
    verdict = FusionPipeline().verdict_for(artifact, [artifact])
    assert verdict.state == VerdictState.MALICIOUS
    assert not any("CAPE" in action for action in verdict.pending_actions)


# -- Multi-artifact --

def test_child_artifact_observations_included():
    root = _make_artifact(provenance_trusted=True, baseline_matched=True, baseline_id="bl-1", baseline_distance=0.0)
    child = _make_artifact(observations=[_obs(ObservationSeverity.HIGH)])
    child.sha256 = "child"
    verdict = FusionPipeline().verdict_for(root, [root, child])
    assert verdict.state == VerdictState.MALICIOUS
