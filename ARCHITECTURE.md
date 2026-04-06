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
        │          ┌────▼──┐ ┌──▼──┐ ┌─▼───┐ ┌───▼────┐
        │          │ YARA  │ │EMBER│ │Capa │ │Ghidra  │
        │          └───────┘ └─────┘ └─────┘ └────────┘
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
  ┌─────▼─────────┐
  │ LLM Function   │  (opt-in, async)
  │ Analysis       │  → Claude API
  └───────┬────────┘
          │
  ┌───────▼───────┐
  │  Fusion        │  (rule-based + LLM reasoning)
  │  Pipeline      │  → VerdictRecord
  └───────┬────────┘
          │
  ┌───────▼───────┐
  │ Auto YARA Gen  │  (if MALICIOUS, opt-in)
  │ Pipeline       │  → data/yara_rules/auto/
  └────────────────┘
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
│   ├── ember.py        # EMBER feature extraction + LightGBM ML classifier
│   ├── ghidra.py       # Disassembly triage and function promotion
│   ├── capa.py         # Capability detection from strings
│   ├── provenance.py   # Signature/provenance validation
│   ├── angr.py         # Symbolic execution (stub)
│   ├── cape.py         # Dynamic sandbox detonation (stub)
│   └── drakvuf.py      # Anti-evasion dynamic analysis (stub)
└── pipeline/
    ├── ingest.py        # Recursive archive extraction + initial heuristics
    ├── static_analysis.py  # Orchestrates YARA, EMBER, Capa, Ghidra, Provenance
    ├── dynamic_analysis.py # Orchestrates CAPE, DRAKVUF
    ├── symbolic.py      # Orchestrates angr
    ├── llm_function_analysis.py  # LLM reasoning on decompiled functions
    ├── fusion.py        # Verdict generation (rule-based + LLM reasoning)
    └── yara_generation.py  # Auto YARA rule generation from malicious samples
```

## Data Flow

1. **Submission** - Binary uploaded via `POST /submissions` with optional policy and provenance metadata.
2. **Ingest** - File is content-addressed (SHA256), stored, format-detected, and recursively unpacked if it's an archive.
3. **Static Analysis** - YARA pattern matching, EMBER ML classification, capability detection, disassembly triage, and provenance checks run against each artifact.
4. **Baseline Comparison** - Artifacts are compared against the trusted baseline corpus using chunk-hash and function-hash similarity (Jaccard distance).
5. **Dynamic Analysis** - Artifacts are submitted to sandboxes for behavioral analysis (currently stubbed).
6. **Symbolic Execution** - Suspicious regions are queued for targeted symbolic execution (currently stubbed).
7. **LLM Function Analysis** - High-triage decompiled functions are sent to Claude for intent analysis (opt-in, requires `llm_function_analysis_enabled=true` + API key).
8. **Fusion** - All observations, tool results, and baseline distances are aggregated into a verdict: `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, or `INCONCLUSIVE`. When `llm_fusion_enabled=true`, Claude synthesizes all signals and can override the rule-based verdict with reasoning.
9. **Auto YARA Generation** - When a sample is confirmed MALICIOUS with high LLM confidence, Claude generates YARA rules from its distinctive features. Rules are saved to `data/yara_rules/auto/` and automatically picked up by the YARA adapter on the next scan, creating a self-improving feedback loop.

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
| EMBER | `ember` feature extraction + `lightgbm` inference | Entropy + byte-histogram + packer detection | `ember_model_path`, `ember_threshold_*` in Settings |
| capa | `capa` CLI (JSON output via subprocess) | String-based capability detection | `capa_cmd` in Settings |
| Ghidra | `analyzeHeadless` via subprocess + `scripts/ghidra_export.py` | Suspicious region promotion | `ghidra_cmd` in Settings |

When a real tool is unavailable or fails, the adapter transparently falls back to heuristics. The `mode` field in `ToolExecution.details` indicates which backend was used (`"yara-python"`, `"ember"`, `"capa-cli"`, `"ghidra-headless"`, or `"heuristic"`).

Ghidra emits `coverage_gap` observations when the number of functions exceeds the analysis limit or decompilation fails, which feeds into the fusion verdict logic.

## Dynamic Analysis Adapters

| Adapter | Backend | Config |
|---------|---------|--------|
| CAPE | HTTP client to CAPE Sandbox REST API (submit, poll, report) | `cape_cmd` = CAPE URL |
| DRAKVUF | HTTP client to DRAKVUF Sandbox API (submit, poll, report) | `drakvuf_cmd` = DRAKVUF URL |

Both fall back to placeholder stubs when no URL is configured.

## Symbolic Execution (angr)

When `angr` is installed (`pip install angr`) and `enable_symbolic_execution=true` is set in the submission policy:

1. The adapter loads the binary into an `angr.Project`
2. Resolves dangerous sink functions (`system`, `execve`, `connect`, `WriteProcessMemory`, etc.) from the binary's symbol table and PLT/import table
3. For each suspicious function (sorted by Ghidra triage score, capped at `angr_max_functions`), creates a targeted `SimulationManager` exploration
4. If a reachable path to a dangerous sink is found, emits a **HIGH** severity observation with the function name, sink name, path length, and states explored
5. Enforces per-function timeout (`angr_timeout_per_function`, default 60s) and state limit (`angr_max_states`, default 256)

Falls back to a placeholder stub when angr is not installed.

## LLM Function Analysis

When enabled (`SCANNER_LLM_FUNCTION_ANALYSIS_ENABLED=true`) and an Anthropic API key is configured:

1. After symbolic execution, functions with `decompiled_code` and `triage_score >= llm_function_min_triage_score` are selected (sorted by score, capped at `llm_function_max_functions`)
2. Each function's decompiled C code is sent to Claude with binary context (format, strings, prior observations, call graph)
3. Claude analyzes for malicious intent: process injection, C2, persistence, credential theft, evasion, exfiltration
4. Responses are parsed into Observations (`source="llm-function"`) with structured JSON verdicts
5. Token budget (`llm_function_analysis_budget`, default 50k) is tracked separately from source-file LLM analysis

This stage is disabled by default and has no effect on the pipeline when off.

## Repository Analysis

The scanner can analyze entire directory trees, not just individual binaries:

```bash
# CLI (headless, automated heuristics)
uv run python -m security_scanner analyze /path/to/repo --format summary

# Claude Code skill (interactive, AI-guided deep dive)
/analyze /path/to/repo
```

**RepoScanner** (`repo_scanner.py`) walks a directory, classifies files (binary/source/config/script), routes binaries through the existing `AnalysisService.submit()` pipeline, and routes source through `source_analysis.py` heuristic detectors.

**Source heuristic detectors** (`source_analysis.py`):
- Obfuscation: base64 blobs, hex strings, eval/exec, packed JS, `_0x` variable naming
- Suspicious imports: subprocess+socket combos, hardcoded IPs, crypto wallet addresses
- Embedded payloads: PE/ELF headers in source, shellcode hex, long encoded strings
- Dependency risks: typosquatting detection (Levenshtein), malicious post-install scripts
- Secrets: AWS keys, private keys, GitHub tokens, API keys

The `/analyze` Claude Code skill (`.claude/commands/analyze.md`) orchestrates: automated scan → AI triage → sub-agent deep dives → kill chain reconstruction → final report.

## Deployment

```bash
# Local development
uv run python -m security_scanner serve

# Docker (Postgres + Redis + API)
docker compose up

# Create API key (when SCANNER_REQUIRE_AUTH=true)
uv run python -m security_scanner create-key --name "my-key" --scopes submit,read

# Run migrations
uv run python -m security_scanner migrate

# Analyze a repository
uv run python -m security_scanner analyze /path/to/suspicious/repo
```

## CI

GitHub Actions workflow (`.github/workflows/ci.yml`) runs tests and builds the Docker image on every push to `main`.
