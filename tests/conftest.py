from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from security_scanner.api import app
from security_scanner.repository import JsonRepository
from security_scanner.service import AnalysisService
from security_scanner.storage import LocalArtifactStore


@pytest.fixture()
def tmp_service(tmp_path):
    artifact_store = LocalArtifactStore(tmp_path / "artifacts")
    repository = JsonRepository(tmp_path / "state.json")
    return AnalysisService(repository=repository, artifact_store=artifact_store)


@pytest.fixture()
def tmp_client(tmp_path):
    app.state.service = AnalysisService(
        repository=JsonRepository(tmp_path / "state.json"),
        artifact_store=LocalArtifactStore(tmp_path / "artifacts"),
    )
    return TestClient(app)


@pytest.fixture()
def benign_pe_bytes():
    return b"MZ" + (b"\x00" * 64) + b"trusted-binary-content" + (b"A" * 256)


@pytest.fixture()
def malicious_pe_bytes():
    return (
        b"MZ"
        + (b"\x00" * 64)
        + b"CreateRemoteThread"
        + b"WriteProcessMemory"
        + b"VirtualAlloc"
        + b"https://evil.example"
        + (b"B" * 512)
    )


@pytest.fixture()
def malicious_zip(malicious_pe_bytes):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("hidden.exe", malicious_pe_bytes)
    return buf.getvalue()
