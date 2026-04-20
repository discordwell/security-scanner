"""Tests for package-context anomaly detection."""
from __future__ import annotations

from security_scanner.anomaly_scoring import compute_anomaly_scores, anomaly_to_observations
from security_scanner.models import FileClassification, ObservationSeverity, RepoFileRecord


def _file(path, capabilities=None):
    return RepoFileRecord(
        path=path,
        classification=FileClassification.SOURCE,
        size=100,
        sha256="abc",
        metadata={"fingerprint": {"capabilities": capabilities or []}},
    )


def test_no_anomalies_in_uniform_directory():
    """All files have the same capabilities → no anomalies."""
    files = [
        _file("pkg/a.py", ["file_io"]),
        _file("pkg/b.py", ["file_io"]),
        _file("pkg/c.py", ["file_io"]),
        _file("pkg/d.py", ["file_io"]),
    ]
    results = compute_anomaly_scores(files)
    assert len(results) == 0


def test_single_outlier_detected():
    """One file has unique capabilities → flagged as anomalous."""
    files = [
        _file("pkg/a.py", ["file_io"]),
        _file("pkg/b.py", ["file_io"]),
        _file("pkg/c.py", ["file_io"]),
        _file("pkg/outlier.py", ["file_io", "imports_network", "atexit", "network_calls"]),
    ]
    results = compute_anomaly_scores(files)
    assert "pkg/outlier.py" in results
    anomaly = results["pkg/outlier.py"]
    assert anomaly.score > 0.5
    assert "imports_network" in anomaly.anomalous_capabilities
    assert "atexit" in anomaly.anomalous_capabilities


def test_small_directory_skipped():
    """Directories with fewer than min_peers files are skipped."""
    files = [
        _file("pkg/a.py", ["file_io"]),
        _file("pkg/outlier.py", ["imports_network", "atexit"]),
    ]
    results = compute_anomaly_scores(files, min_peers=3)
    assert len(results) == 0


def test_high_score_for_many_unique_capabilities():
    """A file with all unique capabilities gets a high score."""
    files = [
        _file("lib/engine/a.py", []),
        _file("lib/engine/b.py", []),
        _file("lib/engine/c.py", []),
        _file("lib/engine/d.py", ["file_io"]),
        _file("lib/engine/evil.py", ["imports_network", "atexit", "network_calls", "accesses_home"]),
    ]
    results = compute_anomaly_scores(files)
    assert "lib/engine/evil.py" in results
    assert results["lib/engine/evil.py"].score == 1.0  # all 4 caps are unique


def test_anomaly_to_observations_severity():
    """High-scoring anomalies produce HIGH observations."""
    files = [
        _file("pkg/a.py", []),
        _file("pkg/b.py", []),
        _file("pkg/c.py", []),
        _file("pkg/evil.py", ["imports_network", "atexit", "network_calls"]),
    ]
    results = compute_anomaly_scores(files)
    obs_list = anomaly_to_observations(results)
    assert len(obs_list) == 1
    path, obs = obs_list[0]
    assert path == "pkg/evil.py"
    assert obs.severity == ObservationSeverity.HIGH  # score 1.0 > 0.7 threshold
    assert obs.category == "anomaly:context_mismatch"
    assert "imports_network" in obs.message


def test_different_directories_scored_independently():
    """Files in different directories are compared against their own peers."""
    files = [
        # Directory A: network is normal
        _file("net/client.py", ["imports_network", "network_calls"]),
        _file("net/server.py", ["imports_network", "network_calls"]),
        _file("net/pool.py", ["imports_network"]),
        # Directory B: network is anomalous
        _file("models/user.py", ["file_io"]),
        _file("models/post.py", ["file_io"]),
        _file("models/evil.py", ["file_io", "imports_network", "network_calls"]),
    ]
    results = compute_anomaly_scores(files)
    # net/ files should NOT be anomalous (network is normal there)
    assert not any("net/" in path for path in results)
    # models/evil.py SHOULD be anomalous
    assert "models/evil.py" in results


def test_files_without_fingerprint_skipped():
    """Files without fingerprint metadata are gracefully skipped."""
    files = [
        RepoFileRecord(path="pkg/a.py", classification=FileClassification.SOURCE,
                       size=100, sha256="abc", metadata={}),
        _file("pkg/b.py", ["file_io"]),
        _file("pkg/c.py", ["file_io"]),
    ]
    results = compute_anomaly_scores(files)
    assert len(results) == 0  # not enough peers with fingerprints


def test_non_python_files_excluded_from_anomaly_scoring():
    """C++/Rust/Go/Java files use a different capability vocabulary; the anomaly
    scorer is tuned for Python/JS supply-chain patterns and must skip them.
    This prevents FPs on heterogeneous repos (e.g. a Python project vendoring
    a C++ benchmark suite).
    """
    files = [
        _file("src/bench/a.cpp", ["file_io"]),
        _file("src/bench/b.cpp", ["file_io"]),
        _file("src/bench/c.cpp", ["file_io"]),
        _file("src/bench/outlier.cpp", ["imports_network", "atexit", "network_calls"]),
    ]
    results = compute_anomaly_scores(files)
    assert results == {}


def test_mixed_language_directory_only_scores_eligible():
    """In a mixed directory, score the Python files and skip the C++ files.
    Anomaly detection stays useful for the supply-chain-relevant subset."""
    files = [
        _file("mixed/a.py", ["file_io"]),
        _file("mixed/b.py", ["file_io"]),
        _file("mixed/c.py", ["file_io"]),
        _file("mixed/outlier.py", ["imports_network", "atexit", "network_calls"]),
        # C++ peers that would otherwise dilute the "normal" set or get scored
        _file("mixed/vendor1.cpp", ["imports_network"]),
        _file("mixed/vendor2.cpp", ["imports_network"]),
    ]
    results = compute_anomaly_scores(files)
    # Python outlier still detected...
    assert "mixed/outlier.py" in results
    # ...and no C++ file is scored.
    assert not any(p.endswith(".cpp") for p in results)
