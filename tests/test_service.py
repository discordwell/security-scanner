from __future__ import annotations


def test_register_baseline_and_clean_submission(tmp_service, benign_pe_bytes):
    baseline = tmp_service.register_baseline(
        filename="word.exe",
        data=benign_pe_bytes,
        product="Word",
        version="16.0.0.0",
        signer="Microsoft Corporation",
    )

    result = tmp_service.submit(
        filename="word.exe",
        data=benign_pe_bytes,
        claimed_product="Word",
        provenance_bundle={"claimed_signer": "Microsoft Corporation", "authenticode_trusted": True},
    )

    assert baseline.product == "Word"
    assert result.verdict.state.value == "clean"
    assert result.submission.verdict_state.value == "clean"
    assert result.verdict.pending_actions == []


def test_malicious_strings_force_malicious_verdict(tmp_service, malicious_pe_bytes):
    result = tmp_service.submit(
        filename="payload.exe",
        data=malicious_pe_bytes,
        provenance_bundle={"claimed_signer": "Unknown Vendor"},
    )

    assert result.verdict.state.value == "malicious"
    assert any("process injection" in obs.message.lower() for obs in result.verdict.observations)
    assert result.verdict.pending_actions


def test_recursive_archive_analysis_uses_child_artifacts(tmp_service, malicious_zip):
    result = tmp_service.submit(filename="bundle.zip", data=malicious_zip)

    assert result.verdict.state.value == "malicious"
    assert len(result.artifacts) == 2
    assert any(artifact.filename == "hidden.exe" for artifact in result.artifacts)
