from __future__ import annotations


def test_submission_and_lookup_endpoints(tmp_client, benign_pe_bytes):
    baseline_response = tmp_client.post(
        "/baselines",
        files={"file": ("word.exe", benign_pe_bytes, "application/octet-stream")},
        data={"product": "Word", "version": "16.0.0.0", "signer": "Microsoft Corporation"},
    )
    assert baseline_response.status_code == 200

    submission_response = tmp_client.post(
        "/submissions",
        files={"file": ("word.exe", benign_pe_bytes, "application/octet-stream")},
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

    submission_lookup = tmp_client.get(f"/submissions/{submission_id}")
    artifact_lookup = tmp_client.get(f"/artifacts/{artifact_sha}")
    verdict_lookup = tmp_client.get(f"/verdicts/{artifact_sha}")

    assert submission_lookup.status_code == 200
    assert artifact_lookup.status_code == 200
    assert verdict_lookup.status_code == 200
    assert verdict_lookup.json()["state"] == "clean"
