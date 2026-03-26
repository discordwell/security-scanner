from __future__ import annotations

from pathlib import Path

from .config import get_settings


class LocalArtifactStore:
    def __init__(self, root: Path | None = None) -> None:
        settings = get_settings()
        self.root = root or settings.artifact_dir
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, sha256: str, data: bytes) -> str:
        target = self.root / sha256[:2] / sha256
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_bytes(data)
        return str(target)

    def get(self, sha256: str) -> bytes:
        target = self.root / sha256[:2] / sha256
        return target.read_bytes()

    def path_for(self, sha256: str) -> Path:
        return self.root / sha256[:2] / sha256
