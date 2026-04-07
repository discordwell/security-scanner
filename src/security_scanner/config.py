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

    # EMBER ML classification
    ember_model_path: Path = Field(default_factory=lambda: Path.cwd() / "data" / "models" / "ember_lgbm.txt")
    ember_threshold_low: float = 0.3
    ember_threshold_medium: float = 0.7
    ember_threshold_high: float = 0.9
    ember_threshold_critical: float = 0.95

    # Database
    database_url: str = ""

    # Task queue
    redis_url: str = "redis://localhost:6379"
    use_task_queue: bool = False

    # Triage cloud sandbox
    triage_api_key: str = ""
    triage_api_url: str = "https://tria.ge"
    triage_poll_interval: int = 15
    triage_timeout: int = 600

    # Repo analysis
    repo_max_files: int = 5000
    repo_max_file_size: int = 10 * 1024 * 1024
    repo_skip_dirs: list[str] = [".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build"]

    # Anomaly detection
    anomaly_min_peers: int = 3
    anomaly_score_threshold: float = 0.5

    # LLM analysis (optional, requires anthropic SDK + API key)
    llm_enabled: bool = True
    llm_api_key: str = ""
    llm_model: str = "claude-sonnet-4-20250514"
    llm_max_files_per_scan: int = 10
    llm_max_tokens_per_file: int = 4096
    llm_budget_tokens: int = 100_000
    llm_timeout: int = 120
    llm_triage_threshold: int = 20
    llm_triage_max_deep_dive: int = 5
    llm_triage_budget_tokens: int = 15_000

    # LLM fusion verdict reasoning (requires anthropic SDK + API key)
    llm_fusion_enabled: bool = False
    llm_fusion_budget: int = 30_000

    # LLM binary function analysis (requires anthropic SDK + API key)
    llm_function_analysis_enabled: bool = False
    llm_function_analysis_budget: int = 50_000
    llm_function_min_triage_score: float = 0.5
    llm_function_max_functions: int = 5
    llm_function_max_code_length: int = 10_000

    # Auto YARA rule generation (requires anthropic SDK + API key)
    yara_auto_generation_enabled: bool = False
    yara_auto_rules_dir: Path = Field(default_factory=lambda: Path.cwd() / "data" / "yara_rules" / "auto")
    yara_generation_budget: int = 20_000
    yara_generation_min_confidence: float = 0.8

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
