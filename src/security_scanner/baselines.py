from __future__ import annotations

import logging

from .models import ArtifactRecord, BaselineDiff, BaselineRecord

logger = logging.getLogger(__name__)


def build_baseline_record(
    artifact: ArtifactRecord,
    product: str,
    version: str | None,
    signer: str | None,
    metadata: dict[str, str] | None = None,
) -> BaselineRecord:
    return BaselineRecord(
        product=product,
        version=version,
        signer=signer,
        sha256=artifact.sha256,
        format=artifact.format,
        chunk_hashes=artifact.chunk_hashes,
        function_hashes=[function.normalized_hash for function in artifact.functions],
        metadata=metadata or {},
    )


def compare_against_baselines(
    artifact: ArtifactRecord,
    baselines: list[BaselineRecord],
    claimed_product: str | None,
    claimed_signer: str | None,
) -> BaselineDiff:
    candidates = [
        baseline
        for baseline in baselines
        if (claimed_product and baseline.product == claimed_product)
        or (claimed_signer and baseline.signer and baseline.signer == claimed_signer)
    ]
    if not candidates:
        return BaselineDiff(explanation="No applicable baseline was found for this artifact.")

    artifact_chunks = set(artifact.chunk_hashes)
    artifact_functions = {function.normalized_hash for function in artifact.functions}
    best: tuple[float, BaselineRecord, set[str], set[str], int] | None = None

    for baseline in candidates:
        baseline_chunks = set(baseline.chunk_hashes)
        shared_chunks = artifact_chunks & baseline_chunks
        union_chunks = artifact_chunks | baseline_chunks
        chunk_similarity = len(shared_chunks) / len(union_chunks) if union_chunks else 1.0

        baseline_functions = set(baseline.function_hashes)
        shared_functions = artifact_functions & baseline_functions
        union_functions = artifact_functions | baseline_functions
        function_similarity = len(shared_functions) / len(union_functions) if union_functions else chunk_similarity

        similarity = (chunk_similarity * 0.6) + (function_similarity * 0.4)
        distance = round(1.0 - similarity, 4)
        new_regions = sorted(artifact_functions - baseline_functions)[:10]
        missing_regions = sorted(baseline_functions - artifact_functions)[:10]
        candidate = (distance, baseline, new_regions, missing_regions, len(shared_functions))
        if best is None or candidate[0] < best[0]:
            best = candidate

    assert best is not None
    distance, baseline, new_regions, missing_regions, shared_count = best
    matched = distance < 0.2
    explanation = (
        f"Matched baseline {baseline.product} {baseline.version or ''}".strip()
        if matched
        else f"Artifact diverges from baseline {baseline.product} {baseline.version or ''}".strip()
    )
    logger.info("Baseline comparison: %s distance=%.4f matched=%s", baseline.product, distance, matched)
    return BaselineDiff(
        baseline_id=baseline.id,
        matched=matched,
        distance=distance,
        explanation=explanation,
        new_regions=new_regions,
        missing_regions=missing_regions,
        shared_functions=shared_count,
        total_functions=len(artifact_functions),
    )
