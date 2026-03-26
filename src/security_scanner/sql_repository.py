from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .db import ArtifactRow, BaselineRow, SubmissionRow, VerdictRow
from .models import ArtifactRecord, BaselineRecord, SubmissionRecord, VerdictRecord

logger = logging.getLogger(__name__)


class SqlRepository:
    """Repository backed by SQLAlchemy async sessions (Postgres or SQLite)."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    def _artifact_to_row(self, a: ArtifactRecord) -> ArtifactRow:
        d = a.model_dump()
        # JSON-serialize nested Pydantic models for JSON columns
        d_json = a.model_dump(mode="json")
        for key in ("observations", "functions", "behavior", "tool_runs", "provenance", "baseline_diff"):
            d[key] = d_json[key]
        d["metadata_"] = d.pop("metadata", {})
        # Enums to string values for string columns
        d["format"] = d["format"].value if hasattr(d["format"], "value") else d["format"]
        d["kind"] = d["kind"].value if hasattr(d["kind"], "value") else d["kind"]
        return ArtifactRow(**d)

    def _row_to_artifact(self, row: ArtifactRow) -> ArtifactRecord:
        d = {c.key: getattr(row, c.key) for c in ArtifactRow.__table__.columns}
        d["metadata"] = d.pop("metadata_", {})
        return ArtifactRecord.model_validate(d)

    def _submission_to_row(self, s: SubmissionRecord) -> SubmissionRow:
        d = s.model_dump()
        d_json = s.model_dump(mode="json")
        d["policy"] = d_json["policy"]
        d["status"] = d["status"].value if hasattr(d["status"], "value") else d["status"]
        d["verdict_state"] = d["verdict_state"].value if hasattr(d["verdict_state"], "value") else d["verdict_state"]
        return SubmissionRow(**d)

    def _row_to_submission(self, row: SubmissionRow) -> SubmissionRecord:
        d = {c.key: getattr(row, c.key) for c in SubmissionRow.__table__.columns}
        return SubmissionRecord.model_validate(d)

    def _verdict_to_row(self, v: VerdictRecord) -> VerdictRow:
        d = v.model_dump()
        d_json = v.model_dump(mode="json")
        for key in ("observations", "functions", "behavior"):
            d[key] = d_json[key]
        d["state"] = d["state"].value if hasattr(d["state"], "value") else d["state"]
        return VerdictRow(**d)

    def _row_to_verdict(self, row: VerdictRow) -> VerdictRecord:
        d = {c.key: getattr(row, c.key) for c in VerdictRow.__table__.columns}
        return VerdictRecord.model_validate(d)

    def _baseline_to_row(self, b: BaselineRecord) -> BaselineRow:
        d = b.model_dump()
        d["metadata_"] = d.pop("metadata", {})
        d["format"] = d["format"].value if hasattr(d["format"], "value") else d["format"]
        return BaselineRow(**d)

    def _row_to_baseline(self, row: BaselineRow) -> BaselineRecord:
        d = {c.key: getattr(row, c.key) for c in BaselineRow.__table__.columns}
        d["metadata"] = d.pop("metadata_", {})
        return BaselineRecord.model_validate(d)

    async def save_artifact(self, artifact: ArtifactRecord) -> ArtifactRecord:
        async with self._session_factory() as session:
            row = self._artifact_to_row(artifact)
            merged = await session.merge(row)
            await session.commit()
            return self._row_to_artifact(merged)

    async def get_artifact(self, sha256: str) -> ArtifactRecord | None:
        async with self._session_factory() as session:
            row = await session.get(ArtifactRow, sha256)
            return self._row_to_artifact(row) if row else None

    async def save_submission(self, submission: SubmissionRecord) -> SubmissionRecord:
        async with self._session_factory() as session:
            row = self._submission_to_row(submission)
            merged = await session.merge(row)
            await session.commit()
            return self._row_to_submission(merged)

    async def get_submission(self, submission_id: str) -> SubmissionRecord | None:
        async with self._session_factory() as session:
            row = await session.get(SubmissionRow, submission_id)
            return self._row_to_submission(row) if row else None

    async def save_verdict(self, verdict: VerdictRecord) -> VerdictRecord:
        async with self._session_factory() as session:
            row = self._verdict_to_row(verdict)
            merged = await session.merge(row)
            await session.commit()
            return self._row_to_verdict(merged)

    async def get_verdict(self, sha256: str) -> VerdictRecord | None:
        async with self._session_factory() as session:
            row = await session.get(VerdictRow, sha256)
            return self._row_to_verdict(row) if row else None

    async def save_baseline(self, baseline: BaselineRecord) -> BaselineRecord:
        async with self._session_factory() as session:
            row = self._baseline_to_row(baseline)
            merged = await session.merge(row)
            await session.commit()
            return self._row_to_baseline(merged)

    async def list_baselines(self) -> list[BaselineRecord]:
        async with self._session_factory() as session:
            result = await session.execute(select(BaselineRow))
            return [self._row_to_baseline(row) for row in result.scalars().all()]

    async def get_baseline(self, baseline_id: str) -> BaselineRecord | None:
        async with self._session_factory() as session:
            row = await session.get(BaselineRow, baseline_id)
            return self._row_to_baseline(row) if row else None
