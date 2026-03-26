from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_", env_file=".env", extra="ignore")

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
    angr_timeout_per_function: int = 60
    angr_max_states: int = 256
    angr_max_functions: int = 8

    # Database
    database_url: str = ""

    # Task queue
    redis_url: str = "redis://localhost:6379"
    use_task_queue: bool = False

    # Repo analysis
    repo_max_files: int = 5000
    repo_max_file_size: int = 10 * 1024 * 1024
    repo_skip_dirs: list[str] = [".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build"]

    # Auth & security
    require_auth: bool = False
    global_rate_limit: int = 120
    max_upload_bytes: int = 100 * 1024 * 1024
    cors_origins: list[str] = ["*"]

    def ensure_directories(self) -> None:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        if not self.database_url:
            db_path = self.runtime_dir / "scanner.db"
            self.database_url = f"sqlite+aiosqlite:///{db_path}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings
