"""arq worker for background analysis tasks.

Start with: arq security_scanner.worker.WorkerSettings
"""
from __future__ import annotations

import logging

from .config import get_settings
from .db import create_tables, make_engine, make_session_factory
from .models import ExecutionPolicy, ProvenanceBundle, SubmissionStatus
from .service import AnalysisService
from .sql_repository import SqlRepository
from .storage import LocalArtifactStore

logger = logging.getLogger(__name__)


async def analyze_submission(
    ctx: dict,
    submission_id: str,
    filename: str,
    data_hex: str,
    policy_dict: dict | None = None,
    claimed_product: str | None = None,
    provenance_dict: dict | None = None,
) -> dict:
    """Run full analysis pipeline as a background task."""
    service: AnalysisService = ctx["service"]
    data = bytes.fromhex(data_hex)
    policy = ExecutionPolicy.model_validate(policy_dict) if policy_dict else None
    provenance = ProvenanceBundle.model_validate(provenance_dict) if provenance_dict else None

    logger.info("Worker processing submission %s: %s", submission_id, filename)

    result = await service.submit(
        filename=filename,
        data=data,
        policy=policy,
        claimed_product=claimed_product,
        provenance_bundle=provenance,
    )

    return {
        "submission_id": result.submission.id,
        "verdict_state": result.verdict.state.value,
        "artifact_count": len(result.artifacts),
    }


async def startup(ctx: dict) -> None:
    """Initialize the service for the worker."""
    settings = get_settings()
    engine = make_engine(settings.database_url)
    await create_tables(engine)
    session_factory = make_session_factory(engine)
    repository = SqlRepository(session_factory)

    ctx["service"] = AnalysisService(
        repository=repository,
        artifact_store=LocalArtifactStore(),
    )
    ctx["engine"] = engine
    logger.info("Worker started with database: %s", settings.database_url)


async def shutdown(ctx: dict) -> None:
    """Clean up resources."""
    engine = ctx.get("engine")
    if engine:
        await engine.dispose()
    logger.info("Worker shut down")


class WorkerSettings:
    """arq worker settings."""
    functions = [analyze_submission]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = None  # Set from env at import time

    @classmethod
    def configure(cls):
        settings = get_settings()
        try:
            from arq.connections import RedisSettings
            host_port = settings.redis_url.replace("redis://", "").split(":")
            cls.redis_settings = RedisSettings(
                host=host_port[0] or "localhost",
                port=int(host_port[1]) if len(host_port) > 1 else 6379,
            )
        except ImportError:
            pass
