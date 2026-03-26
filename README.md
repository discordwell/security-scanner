# Security Scanner

`security-scanner` is an evidence-first binary analysis harness for executable supply-chain review. The current implementation ships a runnable MVP with:

- a FastAPI submission and verdict API
- immutable content-addressed artifact storage
- recursive container ingestion for common archive formats
- static heuristics for hashing, entropy, strings, suspicious capability detection, and provenance placeholders
- baseline corpus registration and diffing
- explicit adapter seams for Ghidra, YARA, capa, angr, CAPE, and DRAKVUF

The default runtime is local and file-backed so the project can run without a full lab stack. The interfaces are structured so NATS/PostgreSQL/MinIO-backed services can replace the local implementations later.

## Quick start

```bash
uv run uvicorn security_scanner.api:app --reload
```

Submit a sample:

```bash
curl -X POST http://127.0.0.1:8000/submissions \
  -F file=@/path/to/sample.bin \
  -F claimed_product="Word" \
  -F claimed_signer="Microsoft Corporation"
```

Register a trusted baseline:

```bash
curl -X POST http://127.0.0.1:8000/baselines \
  -F file=@/path/to/known-good.bin \
  -F product="Word" \
  -F version="16.0.0.0" \
  -F signer="Microsoft Corporation"
```

Run tests:

```bash
uv run --extra dev pytest
```
