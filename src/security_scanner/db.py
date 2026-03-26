from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text, func
from sqlalchemy.ext.asyncio import AsyncAttrs, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(AsyncAttrs, DeclarativeBase):
    pass


class ArtifactRow(Base):
    __tablename__ = "artifacts"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    sha1: Mapped[str] = mapped_column(String(40))
    md5: Mapped[str] = mapped_column(String(32))
    filename: Mapped[str] = mapped_column(String(512))
    size: Mapped[int] = mapped_column(Integer)
    format: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(32))
    storage_path: Mapped[str] = mapped_column(String(1024))
    parent_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    child_artifacts: Mapped[list] = mapped_column(JSON, default=list)
    strings: Mapped[list] = mapped_column(JSON, default=list)
    observations: Mapped[list] = mapped_column(JSON, default=list)
    functions: Mapped[list] = mapped_column(JSON, default=list)
    behavior: Mapped[list] = mapped_column(JSON, default=list)
    tool_runs: Mapped[list] = mapped_column(JSON, default=list)
    provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    baseline_diff: Mapped[dict] = mapped_column(JSON, default=dict)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    chunk_hashes: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
    )


class SubmissionRow(Base):
    __tablename__ = "submissions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(32), default="received")
    root_sha256: Mapped[str] = mapped_column(String(64))
    artifact_shas: Mapped[list] = mapped_column(JSON, default=list)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    claimed_product: Mapped[str | None] = mapped_column(String(256), nullable=True)
    claimed_signer: Mapped[str | None] = mapped_column(String(256), nullable=True)
    verdict_state: Mapped[str] = mapped_column(String(32), default="inconclusive")
    verdict_summary: Mapped[str] = mapped_column(Text, default="")
    pending_actions: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(),
    )


class VerdictRow(Base):
    __tablename__ = "verdicts"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    state: Mapped[str] = mapped_column(String(32))
    summary: Mapped[str] = mapped_column(Text)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    observations: Mapped[list] = mapped_column(JSON, default=list)
    functions: Mapped[list] = mapped_column(JSON, default=list)
    behavior: Mapped[list] = mapped_column(JSON, default=list)
    pending_actions: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
    )


class BaselineRow(Base):
    __tablename__ = "baselines"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    product: Mapped[str] = mapped_column(String(256))
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signer: Mapped[str | None] = mapped_column(String(256), nullable=True)
    sha256: Mapped[str] = mapped_column(String(64))
    format: Mapped[str] = mapped_column(String(32))
    chunk_hashes: Mapped[list] = mapped_column(JSON, default=list)
    function_hashes: Mapped[list] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
    )


def make_engine(database_url: str, echo: bool = False):
    return create_async_engine(database_url, echo=echo)


def make_session_factory(engine):
    return async_sessionmaker(engine, expire_on_commit=False)


async def create_tables(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
