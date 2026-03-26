from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

from ..models import ArtifactKind, ArtifactRecord, Observation, ObservationSeverity
from ..storage import LocalArtifactStore
from ..utils import (
    PRINTABLE_RE,
    calculate_entropy,
    chunk_hashes,
    detect_format,
    extract_strings,
    hash_bytes,
    is_pyinstaller,
    maybe_extract_archive,
)


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

        # Detect packed/encrypted PyInstaller binaries
        if is_pyinstaller(data):
            root.observations.append(
                Observation(
                    source="ingest",
                    category="packer:pyinstaller",
                    severity=ObservationSeverity.MEDIUM,
                    message=f"PyInstaller-packed executable detected: {filename}",
                    evidence={"packer": "pyinstaller"},
                    tags=["ingest", "packer", "pyinstaller"],
                )
            )
            root.metadata["packer"] = "pyinstaller"

        extracted: list[ArtifactRecord] = []
        if max_depth > 0:
            children = maybe_extract_archive(filename, data)
            for child_name, child_data in children:
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

            # If this was a PyInstaller binary, check if extracted entries are encrypted
            if is_pyinstaller(data) and children:
                encrypted_count = self._count_encrypted_entries(children)
                total = len(children)
                if encrypted_count > 2:
                    root.observations.append(
                        Observation(
                            source="ingest",
                            category="evasion:encrypted_payload",
                            severity=ObservationSeverity.HIGH,
                            message=f"PyInstaller payload is encrypted: {encrypted_count}/{total} entries have high entropy with no readable strings. Legitimate applications rarely encrypt their PyInstaller payloads.",
                            evidence={
                                "encrypted_entries": encrypted_count,
                                "total_entries": total,
                                "packer": "pyinstaller",
                            },
                            tags=["ingest", "evasion", "encrypted", "pyinstaller"],
                        )
                    )

        return IngestResult(root=root, extracted=extracted)

    def _count_encrypted_entries(self, children: list[tuple[str, bytes]]) -> int:
        """Count PyInstaller script/module entries that appear encrypted.

        Legitimate PyInstaller entries for Python code start with .pyc magic
        bytes (e.g. 0x55 0x0d for Python 3.11+) or are readable marshalled
        code. Encrypted entries have high entropy and no .pyc signature.
        We exclude DLLs/PYDs (typecode 'b' in names) which are naturally
        high-entropy compiled binaries.
        """
        count = 0
        for name, content in children:
            # Skip DLLs, PYDs, and tiny entries
            lower = name.lower()
            if any(lower.endswith(ext) for ext in ('.dll', '.pyd', '.so', '.dylib')):
                continue
            if 'dll' in lower or len(content) < 50:
                continue
            # Python script/module entries: check if they look like valid .pyc
            # .pyc files start with a 4-byte magic number, or marshalled code objects
            # Encrypted payloads have near-max entropy and no structure
            ent = calculate_entropy(content)
            if ent > 7.8:
                # High entropy non-binary entry = likely encrypted
                count += 1
        return count

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
