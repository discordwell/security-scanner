from __future__ import annotations

from pathlib import Path

import pytest

from security_scanner.adapters.ember import EmberAdapter, HAS_EMBER
from security_scanner.models import ArtifactFormat, ToolStatus

needs_ember = pytest.mark.skipif(not HAS_EMBER, reason="ember/lightgbm not installed")

MODEL_PATH = Path("data/models/ember_lgbm.txt")
needs_model = pytest.mark.skipif(
    not MODEL_PATH.is_file(),
    reason=f"EMBER model not found at {MODEL_PATH}",
)


# -- Fallback tests (always run, no external deps needed) --


def test_ember_adapter_fallback_without_model():
    adapter = EmberAdapter(model_path=Path("/nonexistent/model.txt"))
    result = adapter.analyze(b"MZ" + b"\x00" * 256, artifact_format=ArtifactFormat.PE)
    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "heuristic"


def test_ember_adapter_fallback_none_model_path():
    adapter = EmberAdapter(model_path=None)
    result = adapter.analyze(b"MZ" + b"\x00" * 256)
    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "heuristic"


def test_ember_adapter_heuristic_benign():
    adapter = EmberAdapter()
    data = b"MZ" + b"\x00" * 64 + b"Hello World" + (b"A" * 256)
    result = adapter.analyze(data)
    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["score"] < 0.3


def test_ember_adapter_heuristic_suspicious():
    """High entropy random data should produce a non-zero score."""
    import os

    adapter = EmberAdapter()
    data = os.urandom(8192)
    result = adapter.analyze(data)
    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["score"] > 0.0


# -- Integration tests (require ember + lightgbm + model file) --


@needs_ember
@needs_model
@pytest.mark.integration
def test_ember_real_classify_pe(malicious_pe_bytes):
    adapter = EmberAdapter(model_path=MODEL_PATH)
    result = adapter.analyze(malicious_pe_bytes, artifact_format=ArtifactFormat.PE)
    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "ember"
    assert "score" in result.tool_run.details


@needs_ember
@needs_model
@pytest.mark.integration
def test_ember_real_benign_pe(benign_pe_bytes):
    adapter = EmberAdapter(model_path=MODEL_PATH)
    result = adapter.analyze(benign_pe_bytes, artifact_format=ArtifactFormat.PE)
    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "ember"


@needs_ember
@needs_model
@pytest.mark.integration
def test_ember_real_observations_have_evidence(malicious_pe_bytes):
    adapter = EmberAdapter(model_path=MODEL_PATH)
    result = adapter.analyze(malicious_pe_bytes, artifact_format=ArtifactFormat.PE)
    if result.observations:
        obs = result.observations[0]
        assert "score" in obs.evidence
        assert "feature_count" in obs.evidence
        assert obs.evidence["mode"] == "ember"
