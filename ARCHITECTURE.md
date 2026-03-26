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
- **State**: Single JSON file at `data/runtime/state.json` holding submissions, verdicts, artifacts, and baselines.
- **Thread Safety**: `JsonRepository` uses `RLock` and atomic temp-file writes.

The interfaces are structured so that NATS/PostgreSQL/MinIO-backed implementations can replace the local file-backed ones.

## Verdict Logic (Fusion)

| Condition | Verdict |
|-----------|---------|
| Any HIGH or CRITICAL observation | MALICIOUS |
| Any MEDIUM observation or baseline distance >= 0.2 | SUSPICIOUS |
| No HIGH/MEDIUM + trusted provenance + baseline match + no coverage gaps | CLEAN |
| None of the above | INCONCLUSIVE |

## Stubbed Components

The following adapters accept configuration but return placeholder results in the current MVP:
- **angr** - symbolic execution
- **CAPE** - dynamic sandbox detonation
- **DRAKVUF** - anti-evasion dynamic analysis

YARA, Ghidra, and Capa adapters use built-in heuristics rather than calling external tools.
