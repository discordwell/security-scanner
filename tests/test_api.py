from __future__ import annotations

from fastapi.testclient import TestClient

from security_scanner.api import app
from security_scanner.repository import JsonRepository
from security_scanner.service import AnalysisService
from security_scanner.storage import LocalArtifactStore


def build_client(tmp_path):
    app.state.service = AnalysisService(
        repository=JsonRepository(tmp_path / "state.json"),
        artifact_store=LocalArtifactStore(tmp_path / "artifacts"),
    )
    return TestClient(app)


def test_submission_and_lookup_endpoints(tmp_path):
    client = build_client(tmp_path)
    sample = b"MZ" + (b"\x00" * 64) + b"trusted-binary-content" + (b"A" * 256)

    baseline_response = client.post(
        "/baselines",
        files={"file": ("word.exe", sample, "application/octet-stream")},
        data={"product": "Word", "version": "16.0.0.0", "signer": "Microsoft Corporation"},
    )
    assert baseline_response.status_code == 200

    submission_response = client.post(
        "/submissions",
        files={"file": ("word.exe", sample, "application/octet-stream")},
        data={
            "claimed_product": "Word",
            "claimed_signer": "Microsoft Corporation",
            "authenticode_trusted": "true",
        },
    )
    assert submission_response.status_code == 200
    payload = submission_response.json()
    assert payload["verdict"]["state"] == "clean"

    submission_id = payload["submission"]["id"]
    artifact_sha = payload["submission"]["root_sha256"]

    submission_lookup = client.get(f"/submissions/{submission_id}")
    artifact_lookup = client.get(f"/artifacts/{artifact_sha}")
    verdict_lookup = client.get(f"/verdicts/{artifact_sha}")

    assert submission_lookup.status_code == 200
    assert artifact_lookup.status_code == 200
    assert verdict_lookup.status_code == 200
    assert verdict_lookup.json()["state"] == "clean"
