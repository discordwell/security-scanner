from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

from ..models import ArtifactKind, ArtifactRecord, Observation, ObservationSeverity
from ..storage import LocalArtifactStore
from ..utils import calculate_entropy, chunk_hashes, detect_format, extract_strings, hash_bytes, maybe_extract_archive


@dataclass(slots=True)
class IngestResult:
    root: ArtifactRecord
    extracted: list[ArtifactRecord] = field(default_factory=list)


class IngestPipeline:
    def __init__(self, artifact_store: LocalArtifactStore) -> None:
        self.artifact_store = artifact_store

    def ingest(
        self,
        filename: str,
        data: bytes,
        max_depth: int,
        max_strings: int,
        kind: ArtifactKind = ArtifactKind.ROOT,
        parent_sha256: str | None = None,
    ) -> IngestResult:
        logger.info("Ingesting %s (%d bytes, depth=%d)", filename, len(data), max_depth)
        root = self._build_artifact(filename, data, kind=kind, parent_sha256=parent_sha256, max_strings=max_strings)
        extracted: list[ArtifactRecord] = []
        if max_depth > 0:
            for child_name, child_data in maybe_extract_archive(filename, data):
                child_result = self.ingest(
                    filename=child_name,
                    data=child_data,
                    max_depth=max_depth - 1,
                    max_strings=max_strings,
                    kind=ArtifactKind.EXTRACTED,
                    parent_sha256=root.sha256,
                )
                root.child_artifacts.append(child_result.root.sha256)
                extracted.append(child_result.root)
                extracted.extend(child_result.extracted)
        return IngestResult(root=root, extracted=extracted)

    def _build_artifact(
        self,
        filename: str,
        data: bytes,
        kind: ArtifactKind,
        parent_sha256: str | None,
        max_strings: int,
    ) -> ArtifactRecord:
        sha256, sha1, md5 = hash_bytes(data)
        storage_path = self.artifact_store.put(sha256, data)
        strings = extract_strings(data, limit=max_strings)
        entropy = calculate_entropy(data)
        observations = [
            Observation(
                source="ingest",
                category="file",
                severity=ObservationSeverity.INFO,
                message=f"Ingested {filename} as {detect_format(filename, data).value}.",
                evidence={"size": len(data)},
                tags=["ingest"],
            ),
            Observation(
                source="ingest",
                category="entropy",
                severity=ObservationSeverity.MEDIUM if entropy >= 7.2 else ObservationSeverity.INFO,
                message=f"Calculated file entropy {entropy:.2f}.",
                evidence={"entropy": entropy},
                tags=["ingest", "entropy"],
            ),
        ]
        return ArtifactRecord(
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            filename=filename,
            size=len(data),
            format=detect_format(filename, data),
            kind=kind,
            storage_path=storage_path,
            parent_sha256=parent_sha256,
            strings=strings,
            observations=observations,
            metadata={"entropy": entropy},
            chunk_hashes=chunk_hashes(data),
        )
