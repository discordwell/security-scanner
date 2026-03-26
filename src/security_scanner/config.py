from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field


class Settings(BaseModel):
    project_root: Path = Field(default_factory=lambda: Path.cwd())
    data_dir: Path = Field(default_factory=lambda: Path.cwd() / "data")
    artifact_dir: Path = Field(default_factory=lambda: Path.cwd() / "data" / "artifacts")
    runtime_dir: Path = Field(default_factory=lambda: Path.cwd() / "data" / "runtime")
    state_file: Path = Field(default_factory=lambda: Path.cwd() / "data" / "runtime" / "state.json")
    max_unpack_depth: int = 2
    max_strings: int = 256
    deep_decompile_limit: int = 8
    suspicious_entropy: float = 7.2
    ghidra_cmd: str | None = None
    yara_cmd: str | None = None
    capa_cmd: str | None = None
    angr_cmd: str | None = None
    cape_cmd: str | None = None
    drakvuf_cmd: str | None = None
    yara_rules_dir: Path = Field(default_factory=lambda: Path.cwd() / "data" / "yara_rules")
    ghidra_project_dir: Path = Field(default_factory=lambda: Path.cwd() / "data" / "ghidra_projects")
    ghidra_timeout: int = 300
    ghidra_max_functions: int = 50

    def ensure_directories(self) -> None:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings
