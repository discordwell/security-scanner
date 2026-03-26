from __future__ import annotations

from security_scanner.baselines import build_baseline_record, compare_against_baselines
from security_scanner.models import (
    ArtifactFormat,
    ArtifactKind,
    ArtifactRecord,
    BaselineRecord,
    FunctionSummary,
)


def _make_artifact(sha256="abc123", chunk_hashes=None, functions=None, filename="test.exe"):
    return ArtifactRecord(
        sha256=sha256,
        sha1="aaa",
        md5="bbb",
        filename=filename,
        size=100,
        format=ArtifactFormat.PE,
        kind=ArtifactKind.ROOT,
        storage_path="/tmp/test",
        chunk_hashes=chunk_hashes or [],
        functions=functions or [],
    )


def _make_function(normalized_hash):
    return FunctionSummary(
        symbol="fn",
        start_address="0x0",
        end_address="0x100",
        triage_score=0.5,
        reason="test",
        normalized_hash=normalized_hash,
    )


# -- build_baseline_record --

def test_build_baseline_record_captures_chunk_and_function_hashes():
    functions = [_make_function("hash_a"), _make_function("hash_b")]
    artifact = _make_artifact(chunk_hashes=["c1", "c2"], functions=functions)
    baseline = build_baseline_record(artifact, product="Word", version="16.0", signer="MS")
    assert baseline.product == "Word"
    assert baseline.version == "16.0"
    assert baseline.signer == "MS"
    assert baseline.chunk_hashes == ["c1", "c2"]
    assert baseline.function_hashes == ["hash_a", "hash_b"]
    assert baseline.sha256 == "abc123"
    assert baseline.format == ArtifactFormat.PE


def test_build_baseline_record_no_functions():
    artifact = _make_artifact(chunk_hashes=["c1"])
    baseline = build_baseline_record(artifact, product="App", version=None, signer=None)
    assert baseline.function_hashes == []
    assert baseline.chunk_hashes == ["c1"]


# -- compare_against_baselines --

def test_compare_no_baselines_returns_default():
    artifact = _make_artifact(chunk_hashes=["c1"])
    diff = compare_against_baselines(artifact, baselines=[], claimed_product="Word", claimed_signer=None)
    assert diff.matched is False
    assert diff.baseline_id is None
    assert "No applicable baseline" in diff.explanation


def test_compare_no_matching_product_returns_default():
    baseline = BaselineRecord(
        product="Excel", sha256="x", format=ArtifactFormat.PE,
        chunk_hashes=["c1"], function_hashes=[],
    )
    artifact = _make_artifact(chunk_hashes=["c1"])
    diff = compare_against_baselines(artifact, baselines=[baseline], claimed_product="Word", claimed_signer=None)
    assert diff.matched is False
    assert diff.baseline_id is None


def test_compare_matching_product_same_artifact():
    baseline = BaselineRecord(
        product="Word", sha256="abc123", format=ArtifactFormat.PE,
        chunk_hashes=["c1", "c2", "c3"], function_hashes=["f1", "f2"],
    )
    functions = [_make_function("f1"), _make_function("f2")]
    artifact = _make_artifact(chunk_hashes=["c1", "c2", "c3"], functions=functions)
    diff = compare_against_baselines(artifact, baselines=[baseline], claimed_product="Word", claimed_signer=None)
    assert diff.matched is True
    assert diff.distance == 0.0
    assert "Matched" in diff.explanation


def test_compare_divergent_artifact():
    baseline = BaselineRecord(
        product="Word", sha256="x", format=ArtifactFormat.PE,
        chunk_hashes=["c1", "c2"], function_hashes=["f1"],
    )
    functions = [_make_function("f99")]
    artifact = _make_artifact(chunk_hashes=["c99"], functions=functions)
    diff = compare_against_baselines(artifact, baselines=[baseline], claimed_product="Word", claimed_signer=None)
    assert diff.matched is False
    assert diff.distance > 0.2
    assert "diverges" in diff.explanation


def test_compare_multiple_baselines_picks_closest():
    close_baseline = BaselineRecord(
        product="Word", sha256="x", format=ArtifactFormat.PE,
        chunk_hashes=["c1", "c2", "c3"], function_hashes=[],
    )
    far_baseline = BaselineRecord(
        product="Word", sha256="y", format=ArtifactFormat.PE,
        chunk_hashes=["other1", "other2"], function_hashes=[],
    )
    artifact = _make_artifact(chunk_hashes=["c1", "c2", "c3"])
    diff = compare_against_baselines(
        artifact, baselines=[far_baseline, close_baseline], claimed_product="Word", claimed_signer=None,
    )
    assert diff.baseline_id == close_baseline.id
    assert diff.matched is True


def test_compare_by_signer_when_no_product():
    baseline = BaselineRecord(
        product="Word", signer="MS Corp", sha256="x", format=ArtifactFormat.PE,
        chunk_hashes=["c1"], function_hashes=[],
    )
    artifact = _make_artifact(chunk_hashes=["c1"])
    diff = compare_against_baselines(artifact, baselines=[baseline], claimed_product=None, claimed_signer="MS Corp")
    assert diff.matched is True
