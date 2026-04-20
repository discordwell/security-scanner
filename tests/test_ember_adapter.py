from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from security_scanner.adapters.ember import EmberAdapter
from security_scanner.models import ArtifactFormat, ObservationSeverity, ToolStatus


# -- Heuristic fallback (no ember/lightgbm installed) --


def test_ember_heuristic_benign_no_observations():
    adapter = EmberAdapter()
    result = adapter.analyze(b"\x00" * 256)
    assert result.observations == []
    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "heuristic"


def test_ember_heuristic_with_malicious_fixture(malicious_pe_bytes):
    adapter = EmberAdapter()
    result = adapter.analyze(malicious_pe_bytes)
    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "heuristic"


def test_ember_heuristic_high_entropy_data():
    """High-entropy data should produce a suspicion score."""
    import os

    data = os.urandom(4096)
    adapter = EmberAdapter(threshold_low=0.1)
    result = adapter.analyze(data)
    assert result.tool_run.status == ToolStatus.PASS
    score = result.tool_run.details["score"]
    assert score > 0.0


def test_ember_heuristic_packed_binary():
    """UPX-packed binary should trigger packer detection."""
    data = b"MZ" + b"\x00" * 64 + b"UPX!" + b"\xff" * 512
    adapter = EmberAdapter()
    result = adapter.analyze(data)
    assert result.tool_run.status == ToolStatus.PASS
    if result.observations:
        assert result.observations[0].source == "ember-heuristic"
        assert "packer_detected" in result.observations[0].evidence["components"]


# -- Score-to-severity mapping --


def test_score_below_low_returns_none():
    adapter = EmberAdapter()
    assert adapter._score_to_severity(0.1) is None
    assert adapter._score_to_severity(0.29) is None


def test_score_low():
    adapter = EmberAdapter()
    assert adapter._score_to_severity(0.3) == ObservationSeverity.LOW
    assert adapter._score_to_severity(0.5) == ObservationSeverity.LOW


def test_score_medium():
    adapter = EmberAdapter()
    assert adapter._score_to_severity(0.7) == ObservationSeverity.MEDIUM
    assert adapter._score_to_severity(0.89) == ObservationSeverity.MEDIUM


def test_score_high():
    adapter = EmberAdapter()
    assert adapter._score_to_severity(0.9) == ObservationSeverity.HIGH
    assert adapter._score_to_severity(0.94) == ObservationSeverity.HIGH


def test_score_critical():
    adapter = EmberAdapter()
    assert adapter._score_to_severity(0.95) == ObservationSeverity.CRITICAL
    assert adapter._score_to_severity(1.0) == ObservationSeverity.CRITICAL


def test_custom_thresholds():
    adapter = EmberAdapter(
        threshold_low=0.5,
        threshold_medium=0.8,
        threshold_high=0.95,
        threshold_critical=0.99,
    )
    assert adapter._score_to_severity(0.49) is None
    assert adapter._score_to_severity(0.5) == ObservationSeverity.LOW
    assert adapter._score_to_severity(0.8) == ObservationSeverity.MEDIUM
    assert adapter._score_to_severity(0.95) == ObservationSeverity.HIGH
    assert adapter._score_to_severity(0.99) == ObservationSeverity.CRITICAL


# -- Mocked ember + lightgbm --


def test_ember_ml_path_high_score():
    """When ember+lightgbm are available and model loaded, ML path runs."""
    np = pytest.importorskip("numpy")

    mock_model = MagicMock()
    mock_model.predict.return_value = np.array([0.92])
    mock_model.num_trees.return_value = 1000

    mock_extractor = MagicMock()
    mock_extractor.feature_vector.return_value = np.zeros(2381)

    adapter = EmberAdapter()
    adapter._model = mock_model
    adapter._extractor = mock_extractor

    result = adapter.analyze(b"MZ" + b"\x00" * 100, artifact_format=ArtifactFormat.PE)

    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "ember"
    assert len(result.observations) == 1
    assert result.observations[0].source == "ember"
    assert result.observations[0].severity == ObservationSeverity.HIGH
    assert result.observations[0].evidence["score"] == 0.92
    mock_extractor.feature_vector.assert_called_once()
    mock_model.predict.assert_called_once()


def test_ember_ml_path_benign_score():
    """Benign score (below low threshold) produces no observations."""
    np = pytest.importorskip("numpy")

    mock_model = MagicMock()
    mock_model.predict.return_value = np.array([0.05])

    mock_extractor = MagicMock()
    mock_extractor.feature_vector.return_value = np.zeros(2381)

    adapter = EmberAdapter()
    adapter._model = mock_model
    adapter._extractor = mock_extractor

    result = adapter.analyze(b"MZ" + b"\x00" * 100, artifact_format=ArtifactFormat.PE)

    assert result.tool_run.status == ToolStatus.PASS
    assert result.observations == []
    assert result.tool_run.details["score"] == 0.05


def test_ember_ml_path_feature_extraction_failure():
    """Feature extraction failure falls back to FAIL status."""
    mock_model = MagicMock()
    mock_extractor = MagicMock()
    mock_extractor.feature_vector.side_effect = ValueError("bad PE")

    adapter = EmberAdapter()
    adapter._model = mock_model
    adapter._extractor = mock_extractor

    result = adapter.analyze(b"not-a-pe", artifact_format=ArtifactFormat.PE)

    assert result.tool_run.status == ToolStatus.FAIL
    assert "bad PE" in result.tool_run.details["error"]


# -- Unsupported format handling --


def test_ember_unsupported_format_with_model():
    """Non-PE format with model loaded returns PASS with no observations."""
    np = pytest.importorskip("numpy")

    mock_model = MagicMock()
    mock_extractor = MagicMock()

    adapter = EmberAdapter()
    adapter._model = mock_model
    adapter._extractor = mock_extractor

    result = adapter.analyze(b"\x7fELF" + b"\x00" * 100, artifact_format=ArtifactFormat.ELF)

    assert result.tool_run.status == ToolStatus.PASS
    assert result.observations == []
    assert "not supported" in result.tool_run.summary
    mock_extractor.feature_vector.assert_not_called()


def test_ember_unknown_format_uses_heuristic():
    """Without model, unknown format uses heuristic fallback."""
    adapter = EmberAdapter()
    result = adapter.analyze(b"\x00" * 256, artifact_format=ArtifactFormat.UNKNOWN)

    assert result.tool_run.status == ToolStatus.PASS
    assert result.tool_run.details["mode"] == "heuristic"


# -- Pipeline integration --


def test_ember_observations_have_correct_tags():
    """EMBER observations should have expected tags."""
    np = pytest.importorskip("numpy")

    mock_model = MagicMock()
    mock_model.predict.return_value = np.array([0.75])
    mock_extractor = MagicMock()
    mock_extractor.feature_vector.return_value = np.zeros(2381)

    adapter = EmberAdapter()
    adapter._model = mock_model
    adapter._extractor = mock_extractor

    result = adapter.analyze(b"MZ" + b"\x00" * 100, artifact_format=ArtifactFormat.PE)

    obs = result.observations[0]
    assert obs.category == "ml:classification"
    assert "static" in obs.tags
    assert "ml" in obs.tags
    assert "ember" in obs.tags


def test_ember_empty_data():
    """Empty data should not crash."""
    adapter = EmberAdapter()
    result = adapter.analyze(b"")
    assert result.tool_run.status == ToolStatus.PASS
