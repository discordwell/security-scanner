from __future__ import annotations

import logging
import math
from pathlib import Path

from ..models import ArtifactFormat, Observation, ObservationSeverity, ToolExecution, ToolStatus
from .types import AdapterResult

logger = logging.getLogger(__name__)

try:
    import ember as _ember
    import lightgbm as _lgb
    import numpy as _np

    HAS_EMBER = True
except ImportError:
    HAS_EMBER = False

# Known packer magic bytes: (signature, name)
_PACKER_SIGNATURES: list[tuple[bytes, str]] = [
    (b"UPX!", "upx"),
    (b"UPX0", "upx"),
    (b"UPX1", "upx"),
    (b"\x00\x00\x00\x00\x00\x00\x00\x00ASPack", "aspack"),
    (b".themida", "themida"),
    (b".vmp0", "vmprotect"),
    (b".vmp1", "vmprotect"),
    (b"PEC2", "pecompact"),
    (b".nsp0", "nspack"),
]


class EmberAdapter:
    """EMBER feature extraction + LightGBM ML classifier for binary malware detection."""

    def __init__(
        self,
        model_path: Path | None = None,
        threshold_low: float = 0.3,
        threshold_medium: float = 0.7,
        threshold_high: float = 0.9,
        threshold_critical: float = 0.95,
    ) -> None:
        self._threshold_low = threshold_low
        self._threshold_medium = threshold_medium
        self._threshold_high = threshold_high
        self._threshold_critical = threshold_critical
        self._model = None
        self._extractor = None
        self._model_path = model_path

        if not HAS_EMBER:
            logger.info("ember/lightgbm not installed; EmberAdapter will use heuristic fallback")
            return

        if model_path and model_path.is_file():
            try:
                self._model = _lgb.Booster(model_file=str(model_path))
                self._extractor = _ember.PEFeatureExtractor(feature_version=2)
                logger.info(
                    "EMBER model loaded from %s (%d trees)",
                    model_path,
                    self._model.num_trees(),
                )
            except (ValueError, OSError, _lgb.basic.LightGBMError) as exc:
                logger.warning("Failed to load EMBER model from %s: %s", model_path, exc)
                self._model = None
                self._extractor = None
        else:
            logger.info("EMBER model not found at %s; using heuristic fallback", model_path)

    def analyze(
        self,
        data: bytes,
        artifact_format: ArtifactFormat = ArtifactFormat.UNKNOWN,
    ) -> AdapterResult:
        if self._model is not None and self._extractor is not None:
            if artifact_format == ArtifactFormat.PE:
                return self._analyze_with_ember(data)
            return self._analyze_unsupported_format(artifact_format)
        return self._analyze_heuristic(data)

    def _analyze_with_ember(self, data: bytes) -> AdapterResult:
        try:
            features = self._extractor.feature_vector(data)
            score = float(self._model.predict(features.reshape(1, -1))[0])
        except Exception as exc:
            logger.warning("EMBER feature extraction failed: %s", exc)
            return AdapterResult(
                tool_run=ToolExecution(
                    tool="ember",
                    status=ToolStatus.FAIL,
                    summary=f"Feature extraction failed: {exc}",
                    details={"mode": "ember", "error": str(exc)},
                ),
            )

        severity = self._score_to_severity(score)
        observations: list[Observation] = []

        if severity is not None:
            observations.append(
                Observation(
                    source="ember",
                    category="ml:classification",
                    severity=severity,
                    message=f"EMBER ML classifier scored {score:.3f} ({severity.value})",
                    evidence={
                        "score": round(score, 4),
                        "threshold_applied": severity.value,
                        "feature_count": len(features),
                        "format": "pe",
                        "mode": "ember",
                    },
                    addresses=[],
                    tags=["static", "ml", "ember", "classification"],
                )
            )

        tool_run = ToolExecution(
            tool="ember",
            status=ToolStatus.PASS,
            summary=f"EMBER ML classification: score={score:.3f}",
            details={
                "mode": "ember",
                "score": round(score, 4),
                "observation_count": len(observations),
                "model_path": str(self._model_path),
            },
        )
        return AdapterResult(observations=observations, tool_run=tool_run)

    def _analyze_unsupported_format(self, artifact_format: ArtifactFormat) -> AdapterResult:
        return AdapterResult(
            tool_run=ToolExecution(
                tool="ember",
                status=ToolStatus.PASS,
                summary=f"EMBER ML: format '{artifact_format.value}' not supported for ML classification",
                details={"mode": "ember", "skipped_format": artifact_format.value},
            ),
        )

    def _analyze_heuristic(self, data: bytes) -> AdapterResult:
        score = self._heuristic_score(data)
        severity = self._score_to_severity(score)
        observations: list[Observation] = []

        if severity is not None:
            observations.append(
                Observation(
                    source="ember-heuristic",
                    category="ml:classification",
                    severity=severity,
                    message=f"Heuristic suspicion score {score:.3f} ({severity.value})",
                    evidence={
                        "score": round(score, 4),
                        "threshold_applied": severity.value,
                        "mode": "heuristic",
                        "components": self._heuristic_components(data),
                    },
                    addresses=[],
                    tags=["static", "ml", "ember", "heuristic"],
                )
            )

        tool_run = ToolExecution(
            tool="ember",
            status=ToolStatus.PASS,
            summary=f"Heuristic suspicion score: {score:.3f}",
            details={
                "mode": "heuristic",
                "score": round(score, 4),
                "observation_count": len(observations),
            },
        )
        return AdapterResult(observations=observations, tool_run=tool_run)

    def _score_to_severity(self, score: float) -> ObservationSeverity | None:
        if score >= self._threshold_critical:
            return ObservationSeverity.CRITICAL
        if score >= self._threshold_high:
            return ObservationSeverity.HIGH
        if score >= self._threshold_medium:
            return ObservationSeverity.MEDIUM
        if score >= self._threshold_low:
            return ObservationSeverity.LOW
        return None

    def _heuristic_score(self, data: bytes) -> float:
        if not data:
            return 0.0
        components = self._heuristic_components(data)
        # Weighted combination: entropy dominates, packing is a strong signal
        score = (
            components["entropy_ratio"] * 0.35
            + components["nonprintable_ratio"] * 0.15
            + components["packer_detected"] * 0.30
            + components["high_entropy_sections"] * 0.20
        )
        return min(max(score, 0.0), 1.0)

    def _heuristic_components(self, data: bytes) -> dict[str, float]:
        entropy = self._entropy(data)
        # Normalize entropy to 0-1 range (max Shannon entropy for bytes is 8.0)
        # Suspicious threshold starts around 6.5
        entropy_ratio = max(0.0, (entropy - 5.0) / 3.0)

        nonprintable = sum(1 for b in data[:4096] if b < 0x20 or b > 0x7E)
        nonprintable_ratio = nonprintable / min(len(data), 4096)

        packer_detected = 1.0 if self._detect_packer(data) else 0.0

        # Check for high-entropy sections (sliding window)
        high_sections = self._high_entropy_section_ratio(data)

        return {
            "entropy_ratio": round(entropy_ratio, 4),
            "nonprintable_ratio": round(nonprintable_ratio, 4),
            "packer_detected": packer_detected,
            "high_entropy_sections": round(high_sections, 4),
        }

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        entropy = 0.0
        size = len(data)
        for count in counts:
            if count == 0:
                continue
            p = count / size
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _detect_packer(data: bytes) -> str | None:
        for sig, name in _PACKER_SIGNATURES:
            if sig in data[:8192]:
                return name
        return None

    @staticmethod
    def _high_entropy_section_ratio(data: bytes) -> float:
        """Fraction of 1KB chunks with entropy > 7.0 (likely encrypted/compressed)."""
        chunk_size = 1024
        if len(data) < chunk_size:
            return 0.0
        high_count = 0
        total = 0
        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            if len(chunk) < chunk_size:
                break
            total += 1
            e = EmberAdapter._entropy(chunk)
            if e > 7.0:
                high_count += 1
        return high_count / total if total else 0.0
