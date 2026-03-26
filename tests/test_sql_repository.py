"""Tests for SqlRepository using in-memory SQLite (aiosqlite)."""
from __future__ import annotations

import pytest

from security_scanner.db import Base, make_engine, make_session_factory
from security_scanner.models import (
    ArtifactFormat,
    ArtifactKind,
    ArtifactRecord,
    BaselineRecord,
    SubmissionRecord,
    SubmissionStatus,
    VerdictRecord,
    VerdictState,
)
from security_scanner.sql_repository import SqlRepository


@pytest.fixture()
async def sql_repo():
    engine = make_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = make_session_factory(engine)
    repo = SqlRepository(session_factory)
    yield repo
    await engine.dispose()


def _make_artifact(sha256="abc123"):
    return ArtifactRecord(
        sha256=sha256,
        sha1="aaa",
        md5="bbb",
        filename="test.exe",
        size=100,
        format=ArtifactFormat.PE,
        kind=ArtifactKind.ROOT,
        storage_path="/tmp/test",
    )


@pytest.mark.asyncio
async def test_save_and_get_artifact(sql_repo):
    artifact = _make_artifact()
    saved = await sql_repo.save_artifact(artifact)
    assert saved.sha256 == "abc123"

    loaded = await sql_repo.get_artifact("abc123")
    assert loaded is not None
    assert loaded.sha256 == "abc123"
    assert loaded.filename == "test.exe"
    assert loaded.format == ArtifactFormat.PE


@pytest.mark.asyncio
async def test_get_missing_artifact(sql_repo):
    result = await sql_repo.get_artifact("nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_save_and_get_submission(sql_repo):
    sub = SubmissionRecord(
        filename="test.exe",
        root_sha256="abc123",
        artifact_shas=["abc123"],
        status=SubmissionStatus.ANALYZING,
    )
    saved = await sql_repo.save_submission(sub)
    assert saved.id == sub.id

    loaded = await sql_repo.get_submission(sub.id)
    assert loaded is not None
    assert loaded.filename == "test.exe"
    assert loaded.status == SubmissionStatus.ANALYZING


@pytest.mark.asyncio
async def test_get_missing_submission(sql_repo):
    result = await sql_repo.get_submission("nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_save_and_get_verdict(sql_repo):
    verdict = VerdictRecord(
        sha256="abc123",
        state=VerdictState.CLEAN,
        summary="All clear.",
        reasons=["Trusted provenance."],
    )
    saved = await sql_repo.save_verdict(verdict)
    assert saved.sha256 == "abc123"

    loaded = await sql_repo.get_verdict("abc123")
    assert loaded is not None
    assert loaded.state == VerdictState.CLEAN
    assert loaded.reasons == ["Trusted provenance."]


@pytest.mark.asyncio
async def test_get_missing_verdict(sql_repo):
    result = await sql_repo.get_verdict("nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_save_and_list_baselines(sql_repo):
    b1 = BaselineRecord(
        product="Word", sha256="aaa", format=ArtifactFormat.PE,
        chunk_hashes=["c1"], function_hashes=["f1"],
    )
    b2 = BaselineRecord(
        product="Excel", sha256="bbb", format=ArtifactFormat.PE,
        chunk_hashes=["c2"], function_hashes=[],
    )
    await sql_repo.save_baseline(b1)
    await sql_repo.save_baseline(b2)

    baselines = await sql_repo.list_baselines()
    assert len(baselines) == 2
    products = {b.product for b in baselines}
    assert products == {"Word", "Excel"}


@pytest.mark.asyncio
async def test_get_baseline(sql_repo):
    b = BaselineRecord(
        product="Word", sha256="aaa", format=ArtifactFormat.PE,
    )
    await sql_repo.save_baseline(b)

    loaded = await sql_repo.get_baseline(b.id)
    assert loaded is not None
    assert loaded.product == "Word"

    missing = await sql_repo.get_baseline("nonexistent")
    assert missing is None


@pytest.mark.asyncio
async def test_upsert_artifact(sql_repo):
    artifact = _make_artifact()
    await sql_repo.save_artifact(artifact)

    artifact.filename = "updated.exe"
    await sql_repo.save_artifact(artifact)

    loaded = await sql_repo.get_artifact("abc123")
    assert loaded.filename == "updated.exe"


@pytest.mark.asyncio
async def test_end_to_end_with_sql_repo(sql_repo):
    """Full submission flow using SqlRepository."""
    from security_scanner.service import AnalysisService
    from security_scanner.storage import LocalArtifactStore
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        service = AnalysisService(
            repository=sql_repo,
            artifact_store=LocalArtifactStore(Path(tmp) / "artifacts"),
        )

        data = b"MZ" + b"\x00" * 64 + b"trusted-binary-content" + b"A" * 256

        baseline = await service.register_baseline(
            filename="word.exe", data=data,
            product="Word", version="16.0", signer="MS",
        )
        assert baseline.product == "Word"

        result = await service.submit(
            filename="word.exe", data=data,
            claimed_product="Word",
            provenance_bundle={"claimed_signer": "MS", "authenticode_trusted": True},
        )
        assert result.verdict.state.value == "clean"

        loaded_sub = await service.get_submission(result.submission.id)
        assert loaded_sub is not None
        assert loaded_sub.verdict_state.value == "clean"
