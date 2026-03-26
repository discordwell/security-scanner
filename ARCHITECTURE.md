# Architecture

## Overview

`security-scanner` is an evidence-first binary analysis harness for executable supply-chain review. It accepts binary samples via a REST API, runs them through a multi-stage analysis pipeline, compares them against a trusted baseline corpus, and produces a verdict with supporting observations.

The system is designed to run locally with file-backed storage while keeping adapter interfaces ready for external tool integration and distributed backends.

## Core Components

```
                        ┌───────────────┐
                        │   FastAPI      │
                        │   api.py       │
                        └──────┬────────┘
                               │
                        ┌──────▼────────┐
                        │ AnalysisService│
                        │  service.py    │
                        └──────┬────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
  ┌─────▼─────┐        ┌──────▼──────┐        ┌──────▼──────┐
  │  Ingest    │        │   Static    │        │  Baselines  │
  │  Pipeline  │        │  Analysis   │        │ baselines.py│
  └─────┬─────┘        └──────┬──────┘        └─────────────┘
        │                      │
        │               ┌──────┼──────────┐
        │               │      │          │
        │          ┌────▼──┐ ┌─▼───┐ ┌───▼────┐
        │          │ YARA  │ │Capa │ │Ghidra  │
        │          └───────┘ └─────┘ └────────┘
        │
  ┌─────▼─────┐        ┌─────────────┐
  │  Dynamic   │        │  Symbolic   │
  │  Analysis  │        │  Pipeline   │
  └─────┬─────┘        └──────┬──────┘
        │                      │
   ┌────┼────┐           ┌────▼────┐
   │    │    │           │  angr   │
 ┌─▼─┐ └──▼───┐         └─────────┘
 │CAPE│ │DRAKVUF│
 └────┘ └──────┘
        │
  ┌─────▼─────┐
  │  Fusion    │
  │  Pipeline  │  → VerdictRecord
  └────────────┘
```

## Directory Layout

```
src/security_scanner/
├── api.py              # FastAPI endpoints (submissions, baselines, lookups)
├── service.py          # AnalysisService orchestrator
├── models.py           # Pydantic domain models and enums
├── config.py           # Settings (paths, tool commands)
├── storage.py          # Content-addressed artifact store (SHA256)
├── repository.py       # JSON-backed state persistence (thread-safe)
├── baselines.py        # Baseline registration and fuzzy comparison
├── utils.py            # Hashing, entropy, strings, format detection
├── __main__.py         # CLI entry point (uvicorn)
├── adapters/
│   ├── types.py        # AdapterResult dataclass
│   ├── yara.py         # Pattern-based heuristic scanner
│   ├── ghidra.py       # Disassembly triage and function promotion
│   ├── capa.py         # Capability detection from strings
│   ├── provenance.py   # Signature/provenance validation
│   ├── angr.py         # Symbolic execution (stub)
│   ├── cape.py         # Dynamic sandbox detonation (stub)
│   └── drakvuf.py      # Anti-evasion dynamic analysis (stub)
└── pipeline/
    ├── ingest.py        # Recursive archive extraction + initial heuristics
    ├── static_analysis.py  # Orchestrates YARA, Capa, Ghidra, Provenance
    ├── dynamic_analysis.py # Orchestrates CAPE, DRAKVUF
    ├── symbolic.py      # Orchestrates angr
    └── fusion.py        # Verdict generation from aggregated evidence
```

## Data Flow

1. **Submission** - Binary uploaded via `POST /submissions` with optional policy and provenance metadata.
2. **Ingest** - File is content-addressed (SHA256), stored, format-detected, and recursively unpacked if it's an archive.
3. **Static Analysis** - YARA-style pattern matching, capability detection, disassembly triage, and provenance checks run against each artifact.
4. **Baseline Comparison** - Artifacts are compared against the trusted baseline corpus using chunk-hash and function-hash similarity (Jaccard distance).
5. **Dynamic Analysis** - Artifacts are submitted to sandboxes for behavioral analysis (currently stubbed).
6. **Symbolic Execution** - Suspicious regions are queued for targeted symbolic execution (currently stubbed).
7. **Fusion** - All observations, tool results, and baseline distances are aggregated into a verdict: `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, or `INCONCLUSIVE`.

## Storage

- **Artifacts**: Content-addressed file store under `data/artifacts/{sha256}/blob`.
- **State**: Dual-backend via `Repository` protocol:
  - `JsonRepository` -- single JSON file at `data/runtime/state.json` (thread-safe via `RLock`, for local dev)
  - `SqlRepository` -- SQLAlchemy async with SQLite (`aiosqlite`) or PostgreSQL (`asyncpg`)
- **Migrations**: Alembic for schema management (`src/security_scanner/migrations/`)
- **Config**: `pydantic-settings` `BaseSettings` with `SCANNER_` env prefix (e.g. `SCANNER_DATABASE_URL`)

## Async Architecture

The `AnalysisService` is fully async. CPU-bound pipeline stages (ingest, static analysis) are dispatched via `asyncio.to_thread`. The `_RepoAdapter` wraps both sync (`JsonRepository`) and async (`SqlRepository`) backends with a uniform async interface.

Optional arq worker (`src/security_scanner/worker.py`) enables background task processing when `SCANNER_USE_TASK_QUEUE=true` and Redis is available.

## Verdict Logic (Fusion)

| Condition | Verdict |
|-----------|---------|
| Any HIGH or CRITICAL observation | MALICIOUS |
| Any MEDIUM observation or baseline distance >= 0.2 | SUSPICIOUS |
| No HIGH/MEDIUM + trusted provenance + baseline match + no coverage gaps | CLEAN |
| None of the above | INCONCLUSIVE |

## Tool Integration

Each static analysis adapter supports a real tool backend with automatic fallback to built-in heuristics:

| Adapter | Real Tool | Fallback | Config |
|---------|-----------|----------|--------|
| YARA | `yara-python` library, rules from `data/yara_rules/` | Pattern-based string matching | `yara_rules_dir` in Settings |
| capa | `capa` CLI (JSON output via subprocess) | String-based capability detection | `capa_cmd` in Settings |
| Ghidra | `analyzeHeadless` via subprocess + `scripts/ghidra_export.py` | Suspicious region promotion | `ghidra_cmd` in Settings |

When a real tool is unavailable or fails, the adapter transparently falls back to heuristics. The `mode` field in `ToolExecution.details` indicates which backend was used (`"yara-python"`, `"capa-cli"`, `"ghidra-headless"`, or `"heuristic"`).

Ghidra emits `coverage_gap` observations when the number of functions exceeds the analysis limit or decompilation fails, which feeds into the fusion verdict logic.

## Stubbed Components

The following adapters accept configuration but return placeholder results:
- **angr** - symbolic execution
- **CAPE** - dynamic sandbox detonation
- **DRAKVUF** - anti-evasion dynamic analysis
