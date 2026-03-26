"""Tests for middleware (security headers, request size limits, health)."""
from __future__ import annotations


def test_security_headers_present(tmp_client):
    response = tmp_client.get("/")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"


def test_health_endpoint(tmp_client):
    response = tmp_client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] in ("healthy", "degraded")
    assert "checks" in payload
    assert payload["checks"]["api"] == "ok"


def test_oversized_upload_returns_413(tmp_client):
    # Send a content-length header that exceeds the limit
    response = tmp_client.post(
        "/submissions",
        files={"file": ("big.bin", b"x" * 100, "application/octet-stream")},
        headers={"content-length": str(200 * 1024 * 1024)},
    )
    assert response.status_code == 413
