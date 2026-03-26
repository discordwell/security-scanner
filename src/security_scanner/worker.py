"""arq worker for background analysis tasks.

Start with: arq security_scanner.worker.WorkerSettings
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from .config import get_settings
from .db import create_tables, make_engine, make_session_factory
from .models import ExecutionPolicy, ProvenanceBundle
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


def _redact_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.password:
        return parsed._replace(netloc=f"{parsed.username}:***@{parsed.hostname}:{parsed.port}").geturl()
    return url


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
    logger.info("Worker started with database: %s", _redact_url(settings.database_url))


async def shutdown(ctx: dict) -> None:
    """Clean up resources."""
    engine = ctx.get("engine")
    if engine:
        await engine.dispose()
    logger.info("Worker shut down")


def _parse_redis_settings():
    try:
        from arq.connections import RedisSettings
    except ImportError:
        return None

    settings = get_settings()
    parsed = urlparse(settings.redis_url)
    return RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        password=parsed.password,
        database=int(parsed.path.lstrip("/") or 0),
    )


class WorkerSettings:
    """arq worker settings."""
    functions = [analyze_submission]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = _parse_redis_settings()
