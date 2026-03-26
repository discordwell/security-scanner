from __future__ import annotations

import io
import zipfile

import pytest

from security_scanner.models import ExecutionPolicy


@pytest.mark.asyncio
async def test_register_baseline_and_clean_submission(tmp_service, benign_pe_bytes):
    baseline = await tmp_service.register_baseline(
        filename="word.exe",
        data=benign_pe_bytes,
        product="Word",
        version="16.0.0.0",
        signer="Microsoft Corporation",
    )

    result = await tmp_service.submit(
        filename="word.exe",
        data=benign_pe_bytes,
        claimed_product="Word",
        provenance_bundle={"claimed_signer": "Microsoft Corporation", "authenticode_trusted": True},
    )

    assert baseline.product == "Word"
    assert result.verdict.state.value == "clean"
    assert result.submission.verdict_state.value == "clean"
    assert result.verdict.pending_actions == []


@pytest.mark.asyncio
async def test_malicious_strings_force_malicious_verdict(tmp_service, malicious_pe_bytes):
    result = await tmp_service.submit(
        filename="payload.exe",
        data=malicious_pe_bytes,
        provenance_bundle={"claimed_signer": "Unknown Vendor"},
    )

    assert result.verdict.state.value == "malicious"
    assert any("process injection" in obs.message.lower() for obs in result.verdict.observations)
    assert result.verdict.pending_actions


@pytest.mark.asyncio
async def test_recursive_archive_analysis_uses_child_artifacts(tmp_service, malicious_zip):
    result = await tmp_service.submit(filename="bundle.zip", data=malicious_zip)

    assert result.verdict.state.value == "malicious"
    assert len(result.artifacts) == 2
    assert any(artifact.filename == "hidden.exe" for artifact in result.artifacts)


@pytest.mark.asyncio
async def test_max_depth_zero_does_not_extract_children(tmp_service, malicious_zip):
    policy = ExecutionPolicy(recursive_unpack_depth=0)
    result = await tmp_service.submit(filename="bundle.zip", data=malicious_zip, policy=policy)
    assert len(result.artifacts) == 1


@pytest.mark.asyncio
async def test_nested_archive_respects_depth_limit(tmp_service, malicious_pe_bytes):
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as zf:
        zf.writestr("payload.exe", malicious_pe_bytes)
    outer_buf = io.BytesIO()
    with zipfile.ZipFile(outer_buf, "w") as zf:
        zf.writestr("inner.zip", inner_buf.getvalue())

    policy = ExecutionPolicy(recursive_unpack_depth=1)
    result = await tmp_service.submit(filename="outer.zip", data=outer_buf.getvalue(), policy=policy)
    assert len(result.artifacts) == 2
    filenames = {a.filename for a in result.artifacts}
    assert "inner.zip" in filenames
    assert "payload.exe" not in filenames
