from __future__ import annotations


def test_root_endpoint_returns_ok(tmp_client):
    response = tmp_client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_empty_file_submission_returns_400(tmp_client):
    response = tmp_client.post(
        "/submissions",
        files={"file": ("empty.bin", b"", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_empty_file_baseline_returns_400(tmp_client):
    response = tmp_client.post(
        "/baselines",
        files={"file": ("empty.bin", b"", "application/octet-stream")},
        data={"product": "Test"},
    )
    assert response.status_code == 400


def test_missing_submission_returns_404(tmp_client):
    response = tmp_client.get("/submissions/nonexistent-id")
    assert response.status_code == 404


def test_missing_artifact_returns_404(tmp_client):
    response = tmp_client.get("/artifacts/0000000000000000000000000000000000000000000000000000000000000000")
    assert response.status_code == 404


def test_missing_verdict_returns_404(tmp_client):
    response = tmp_client.get("/verdicts/0000000000000000000000000000000000000000000000000000000000000000")
    assert response.status_code == 404


def test_submission_returns_artifacts_and_verdict(tmp_client, benign_pe_bytes):
    response = tmp_client.post(
        "/submissions",
        files={"file": ("test.bin", benign_pe_bytes, "application/octet-stream")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "submission" in payload
    assert "verdict" in payload
    assert "artifacts" in payload
    assert len(payload["artifacts"]) >= 1
