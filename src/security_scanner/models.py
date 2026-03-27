from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


class ArtifactKind(str, Enum):
    ROOT = "root"
    EXTRACTED = "extracted"
    MEMORY_DUMP = "memory_dump"
    REPORT = "report"


class ArtifactFormat(str, Enum):
    PE = "pe"
    ELF = "elf"
    MACH_O = "mach_o"
    ZIP = "zip"
    TAR = "tar"
    GZIP = "gzip"
    UNKNOWN = "unknown"


class ObservationSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNAVAILABLE = "unavailable"


class SubmissionStatus(str, Enum):
    RECEIVED = "received"
    ANALYZING = "analyzing"
    COMPLETE = "complete"


class VerdictState(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"


class ExecutionPolicy(BaseModel):
    allow_external_intel: bool = False
    enable_dynamic_analysis: bool = False
    enable_symbolic_execution: bool = False
    recursive_unpack_depth: int = 2
    deep_decompile_limit: int = 8
    max_strings: int = 256


class ProvenanceBundle(BaseModel):
    claimed_signer: str | None = None
    authenticode_trusted: bool | None = None
    sigstore_subject: str | None = None
    in_toto_layout: str | None = None


class Observation(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    source: str
    category: str
    severity: ObservationSeverity
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    addresses: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class FunctionSummary(BaseModel):
    symbol: str
    start_address: str
    end_address: str
    triage_score: float
    reason: str
    normalized_hash: str
    decompiled: bool = False
    evidence: dict[str, Any] = Field(default_factory=dict)


class BehaviorEvent(BaseModel):
    source: str
    kind: str
    timestamp: datetime = Field(default_factory=utc_now)
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    addresses: list[str] = Field(default_factory=list)


class ToolExecution(BaseModel):
    tool: str
    status: ToolStatus
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


class ProvenanceSummary(BaseModel):
    signer: str | None = None
    authenticode_status: str = "unknown"
    sigstore_status: str = "unknown"
    in_toto_status: str = "unknown"
    trusted: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class BaselineDiff(BaseModel):
    baseline_id: str | None = None
    matched: bool = False
    distance: float = 1.0
    explanation: str = "No baseline comparison available."
    new_regions: list[str] = Field(default_factory=list)
    missing_regions: list[str] = Field(default_factory=list)
    shared_functions: int = 0
    total_functions: int = 0


class ArtifactRecord(BaseModel):
    sha256: str
    sha1: str
    md5: str
    filename: str
    size: int
    format: ArtifactFormat
    kind: ArtifactKind
    storage_path: str
    created_at: datetime = Field(default_factory=utc_now)
    parent_sha256: str | None = None
    child_artifacts: list[str] = Field(default_factory=list)
    strings: list[str] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    functions: list[FunctionSummary] = Field(default_factory=list)
    behavior: list[BehaviorEvent] = Field(default_factory=list)
    tool_runs: list[ToolExecution] = Field(default_factory=list)
    provenance: ProvenanceSummary = Field(default_factory=ProvenanceSummary)
    baseline_diff: BaselineDiff = Field(default_factory=BaselineDiff)
    metadata: dict[str, Any] = Field(default_factory=dict)
    chunk_hashes: list[str] = Field(default_factory=list)


class VerdictRecord(BaseModel):
    sha256: str
    state: VerdictState
    summary: str
    reasons: list[str] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    functions: list[FunctionSummary] = Field(default_factory=list)
    behavior: list[BehaviorEvent] = Field(default_factory=list)
    pending_actions: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class SubmissionRecord(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    filename: str
    status: SubmissionStatus = SubmissionStatus.RECEIVED
    root_sha256: str
    artifact_shas: list[str] = Field(default_factory=list)
    policy: ExecutionPolicy = Field(default_factory=ExecutionPolicy)
    claimed_product: str | None = None
    claimed_signer: str | None = None
    verdict_state: VerdictState = VerdictState.INCONCLUSIVE
    verdict_summary: str = ""
    pending_actions: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class BaselineRecord(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    product: str
    version: str | None = None
    signer: str | None = None
    sha256: str
    format: ArtifactFormat
    chunk_hashes: list[str] = Field(default_factory=list)
    function_hashes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class FileClassification(str, Enum):
    BINARY = "binary"
    SOURCE = "source"
    CONFIG = "config"
    SCRIPT = "script"
    UNKNOWN = "unknown"


class RepoFileRecord(BaseModel):
    path: str
    classification: FileClassification
    size: int
    sha256: str
    observations: list[Observation] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RepoReport(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    repo_path: str
    scanned_at: datetime = Field(default_factory=utc_now)
    file_count: int = 0
    files: list[RepoFileRecord] = Field(default_factory=list)
    binary_verdicts: list[VerdictRecord] = Field(default_factory=list)
    aggregate_verdict: VerdictState = VerdictState.INCONCLUSIVE
    risk_summary: str = ""
    top_findings: list[Observation] = Field(default_factory=list)
    statistics: dict[str, Any] = Field(default_factory=dict)
    cross_file_leads: list[dict[str, Any]] = Field(default_factory=list)
    llm_analysis_targets: list[dict[str, Any]] = Field(default_factory=list)
    llm_findings: list[Observation] = Field(default_factory=list)
    llm_statistics: dict[str, Any] = Field(default_factory=dict)


class StateSnapshot(BaseModel):
    artifacts: dict[str, ArtifactRecord] = Field(default_factory=dict)
    submissions: dict[str, SubmissionRecord] = Field(default_factory=dict)
    verdicts: dict[str, VerdictRecord] = Field(default_factory=dict)
    baselines: dict[str, BaselineRecord] = Field(default_factory=dict)
