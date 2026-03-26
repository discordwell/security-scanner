from __future__ import annotations

import hashlib
import logging
import secrets
from dataclasses import dataclass
from uuid import uuid4

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .db import ApiKeyRow

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ApiKeyInfo:
    id: str
    name: str
    scopes: list[str]
    rate_limit: int


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def create_api_key(
    session_factory: async_sessionmaker[AsyncSession],
    name: str,
    scopes: list[str] | None = None,
    rate_limit: int = 60,
) -> tuple[str, str]:
    """Create a new API key. Returns (key_id, raw_key). The raw key is shown once."""
    raw_key = f"sk-{secrets.token_urlsafe(32)}"
    key_id = uuid4().hex
    row = ApiKeyRow(
        id=key_id,
        key_hash=hash_key(raw_key),
        name=name,
        scopes=scopes or ["submit", "read"],
        rate_limit=rate_limit,
    )
    async with session_factory() as session:
        session.add(row)
        await session.commit()
    logger.info("Created API key '%s' (id=%s)", name, key_id)
    return key_id, raw_key


async def verify_api_key(
    session_factory: async_sessionmaker[AsyncSession],
    raw_key: str,
) -> ApiKeyInfo | None:
    """Verify an API key and return its info, or None if invalid/revoked."""
    key_hash_val = hash_key(raw_key)
    async with session_factory() as session:
        result = await session.execute(
            select(ApiKeyRow).where(
                ApiKeyRow.key_hash == key_hash_val,
                ApiKeyRow.revoked_at.is_(None),
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return ApiKeyInfo(
            id=row.id,
            name=row.name,
            scopes=row.scopes,
            rate_limit=row.rate_limit,
        )


def require_auth(request: Request) -> ApiKeyInfo | None:
    """FastAPI dependency that enforces API key auth when enabled.

    Returns ApiKeyInfo if auth is required, or None if auth is disabled.
    Must be used with Depends() -- the actual verification is async so
    this returns a sub-dependency factory.
    """
    pass  # Replaced by the factory below


async def _extract_and_verify(request: Request) -> ApiKeyInfo | None:
    """Extract bearer token and verify against the database."""
    settings = getattr(request.app.state, "settings", None)
    if settings is None or not getattr(settings, "require_auth", False):
        return None

    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        return None

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")

    raw_key = auth_header[7:]
    info = await verify_api_key(session_factory, raw_key)
    if info is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key.")

    request.state.api_key = info
    return info


def require_scope(scope: str):
    """Factory that returns a dependency requiring a specific scope."""
    async def check_scope(key_info: ApiKeyInfo | None = Depends(_extract_and_verify)):
        if key_info is None:
            return  # Auth disabled
        if scope not in key_info.scopes:
            raise HTTPException(
                status_code=403,
                detail=f"API key does not have the '{scope}' scope.",
            )
        return key_info
    return check_scope
