"""Package-context anomaly detection.

Compares each file's semantic fingerprint against the "normal" profile
for its directory. A file that imports urllib.request in a directory
where no other file does is flagged as anomalous -- regardless of what
strings it contains or how they're obfuscated.

This is the obfuscation-agnostic detection layer.
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .models import Observation, ObservationSeverity, RepoFileRecord
from .semantic_fingerprint import SemanticFingerprint

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AnomalyResult:
    score: float
    anomalous_capabilities: list[str]
    directory: str
    peer_count: int
    normal_capabilities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "anomalous_capabilities": self.anomalous_capabilities,
            "directory": self.directory,
            "peer_count": self.peer_count,
            "normal_capabilities": self.normal_capabilities,
        }


# Anomaly scoring was built around Python/JS supply-chain capability profiles.
# On C/C++/Go/Rust/Java code it tends to fire spuriously because the regex-based
# fingerprint matches bare words like "socket" in comments and the capability
# vocabulary doesn't describe those languages well.
_ELIGIBLE_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}


def _is_eligible_for_anomaly(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in _ELIGIBLE_EXTENSIONS


def compute_anomaly_scores(
    files: list[RepoFileRecord],
    min_peers: int = 3,
    threshold_pct: float = 0.2,
) -> dict[str, AnomalyResult]:
    """Score each file's fingerprint against its directory peers.

    Groups files by parent directory. For each directory with enough peers,
    computes which capabilities are "normal" (present in >= threshold_pct of
    files). Files with capabilities outside the normal set are scored by how
    many anomalous capabilities they have.

    Peer grouping includes every fingerprinted file (so single-script packages
    still have config/doc peers to compare against), but only supply-chain-
    relevant languages (Python/JS/TS) are *scored*. Non-eligible files
    (C/C++/Rust/Go/Java/etc.) are excluded from scoring because their
    regex-based fingerprints tend to match stray keywords in comments and
    the capability vocabulary doesn't describe those languages well.

    :param files: All scanned file records (must have fingerprints in metadata).
    :param min_peers: Minimum files in a directory to run anomaly detection.
    :param threshold_pct: Fraction of files that must share a capability for it to be "normal".
    """
    # Group all fingerprinted files by directory (non-eligible files still
    # contribute to peer count and normal-capability baseline).
    dir_groups: dict[str, list[RepoFileRecord]] = {}
    for f in files:
        fp_dict = f.metadata.get("fingerprint")
        if not fp_dict:
            continue
        dir_key = str(Path(f.path).parent)
        dir_groups.setdefault(dir_key, []).append(f)

    results: dict[str, AnomalyResult] = {}

    for dir_key, group in dir_groups.items():
        if len(group) < min_peers:
            continue

        # Extract capability sets
        cap_sets: list[tuple[RepoFileRecord, frozenset[str]]] = []
        for f in group:
            fp_dict = f.metadata.get("fingerprint", {})
            caps = frozenset(fp_dict.get("capabilities", []))
            cap_sets.append((f, caps))

        # Build directory profile
        cap_counts: Counter[str] = Counter()
        for _, caps in cap_sets:
            cap_counts.update(caps)

        # A capability is "normal" if it appears in at least 2 files OR threshold% of files
        # (whichever is higher). This prevents a single outlier from making its own
        # capabilities "normal" in small directories.
        min_count = max(2, int(len(group) * threshold_pct))
        normal_caps = {cap for cap, count in cap_counts.items() if count >= min_count}

        # Score each file — but only emit results for eligible-language files.
        # Non-eligible files (C/C++/Rust/Go/etc.) still participated in the
        # normal-capability baseline above so eligible files are compared
        # against a correct peer profile.
        for f, caps in cap_sets:
            if not caps:
                continue
            if not _is_eligible_for_anomaly(f.path):
                continue
            anomalous = caps - normal_caps
            if anomalous:
                score = len(anomalous) / len(caps)
                results[f.path] = AnomalyResult(
                    score=round(score, 3),
                    anomalous_capabilities=sorted(anomalous),
                    directory=dir_key,
                    peer_count=len(group),
                    normal_capabilities=sorted(normal_caps),
                )

    logger.info("Anomaly scoring: %d directories analyzed, %d anomalous files found",
                len(dir_groups), len(results))
    return results


def anomaly_to_observations(
    results: dict[str, AnomalyResult],
    high_threshold: float = 0.7,
) -> list[tuple[str, Observation]]:
    """Convert anomaly results to Observation objects.

    Returns list of (file_path, observation) tuples for attachment to file records.
    """
    obs_list: list[tuple[str, Observation]] = []
    for path, anomaly in results.items():
        severity = ObservationSeverity.HIGH if anomaly.score >= high_threshold else ObservationSeverity.MEDIUM
        caps_str = ", ".join(anomaly.anomalous_capabilities)
        obs = Observation(
            source="anomaly-detection",
            category="anomaly:context_mismatch",
            severity=severity,
            message=(
                f"File {path} is anomalous for its directory ({anomaly.directory}, "
                f"{anomaly.peer_count} peers): capabilities [{caps_str}] are unique "
                f"in this context (score: {anomaly.score:.0%})."
            ),
            evidence=anomaly.to_dict(),
            tags=["anomaly", "context_mismatch"] + anomaly.anomalous_capabilities,
        )
        obs_list.append((path, obs))
    return obs_list
