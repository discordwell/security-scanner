from __future__ import annotations

import io
import zipfile

from security_scanner.repository import JsonRepository
from security_scanner.service import AnalysisService
from security_scanner.storage import LocalArtifactStore


def build_service(tmp_path):
    artifact_store = LocalArtifactStore(tmp_path / "artifacts")
    repository = JsonRepository(tmp_path / "state.json")
    return AnalysisService(repository=repository, artifact_store=artifact_store)


def benign_pe_bytes() -> bytes:
    return b"MZ" + (b"\x00" * 64) + b"trusted-binary-content" + (b"A" * 256)


def malicious_pe_bytes() -> bytes:
    return (
        b"MZ"
        + (b"\x00" * 64)
        + b"CreateRemoteThread"
        + b"WriteProcessMemory"
        + b"VirtualAlloc"
        + b"https://evil.example"
        + (b"B" * 512)
    )


def test_register_baseline_and_clean_submission(tmp_path):
    service = build_service(tmp_path)
    sample = benign_pe_bytes()

    baseline = service.register_baseline(
        filename="word.exe",
        data=sample,
        product="Word",
        version="16.0.0.0",
        signer="Microsoft Corporation",
    )

    result = service.submit(
        filename="word.exe",
        data=sample,
        claimed_product="Word",
        provenance_bundle={"claimed_signer": "Microsoft Corporation", "authenticode_trusted": True},
    )

    assert baseline.product == "Word"
    assert result.verdict.state.value == "clean"
    assert result.submission.verdict_state.value == "clean"
    assert result.verdict.pending_actions == []


def test_malicious_strings_force_malicious_verdict(tmp_path):
    service = build_service(tmp_path)
    result = service.submit(
        filename="payload.exe",
        data=malicious_pe_bytes(),
        provenance_bundle={"claimed_signer": "Unknown Vendor"},
    )

    assert result.verdict.state.value == "malicious"
    assert any("process injection" in observation.message.lower() for observation in result.verdict.observations)
    assert result.verdict.pending_actions


def test_recursive_archive_analysis_uses_child_artifacts(tmp_path):
    service = build_service(tmp_path)
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("hidden.exe", malicious_pe_bytes())

    result = service.submit(filename="bundle.zip", data=archive_buffer.getvalue())

    assert result.verdict.state.value == "malicious"
    assert len(result.artifacts) == 2
    assert any(artifact.filename == "hidden.exe" for artifact in result.artifacts)
