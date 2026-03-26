"""Tests for API key authentication."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from security_scanner.api import app
from security_scanner.auth import create_api_key, hash_key
from security_scanner.config import Settings
from security_scanner.db import Base, make_engine, make_session_factory
from security_scanner.repository import JsonRepository
from security_scanner.service import AnalysisService
from security_scanner.storage import LocalArtifactStore


@pytest.fixture()
async def auth_client(tmp_path):
    """TestClient with auth enabled and a database for API keys."""
    engine = make_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = make_session_factory(engine)

    settings = Settings(require_auth=True)
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.service = AnalysisService(
        repository=JsonRepository(tmp_path / "state.json"),
        artifact_store=LocalArtifactStore(tmp_path / "artifacts"),
    )

    yield TestClient(app), session_factory

    await engine.dispose()
    # Reset to no-auth for other tests
    app.state.settings = Settings(require_auth=False)
    if hasattr(app.state, "session_factory"):
        del app.state.session_factory


@pytest.mark.asyncio
async def test_unauthenticated_request_returns_401(auth_client):
    client, _ = auth_client
    response = client.get("/submissions/test-id")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_invalid_key_returns_401(auth_client):
    client, _ = auth_client
    response = client.get(
        "/submissions/test-id",
        headers={"Authorization": "Bearer sk-invalid-key"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_valid_key_passes(auth_client):
    client, session_factory = auth_client
    _, raw_key = await create_api_key(session_factory, name="test-key", scopes=["submit", "read"])

    response = client.get(
        "/submissions/test-id",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    # Should get 404 (not found) rather than 401 (unauthorized)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_insufficient_scope_returns_403(auth_client):
    client, session_factory = auth_client
    _, raw_key = await create_api_key(session_factory, name="read-only", scopes=["read"])

    response = client.post(
        "/submissions",
        files={"file": ("test.bin", b"MZ" + b"\x00" * 100, "application/octet-stream")},
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_missing_bearer_prefix_returns_401(auth_client):
    client, session_factory = auth_client
    _, raw_key = await create_api_key(session_factory, name="test-key")

    response = client.get(
        "/submissions/test-id",
        headers={"Authorization": raw_key},
    )
    assert response.status_code == 401
