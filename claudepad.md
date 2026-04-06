# Claudepad

## Session Summaries

### 2026-04-05T19:00:00Z
- Added EMBER + LightGBM ML classifier adapter for executable malware detection
  - New `EmberAdapter` in `src/security_scanner/adapters/ember.py`
  - Follows existing adapter pattern: graceful degradation with heuristic fallback
  - ML path: EMBER v2 feature extraction (2,381 dims) → LightGBM inference → score → severity
  - Heuristic fallback: entropy analysis + byte-histogram + packer signature detection
  - Score thresholds: <0.3 skip, ≥0.3 LOW, ≥0.7 MEDIUM, ≥0.9 HIGH, ≥0.95 CRITICAL
  - Integrated into static analysis pipeline between YARA and capa
  - 21 new tests (all passing), 357 total tests passing with 0 regressions
  - Download script at `scripts/download_ember_model.py` for pre-trained model
  - Currently PE-only for ML path; non-PE returns INFO; heuristic works on any binary
- Added LLM-powered decompiled function reasoning pipeline
  - Fixed FunctionSummary: added `decompiled_code` field (was discarded after hashing)
  - Updated Ghidra adapter to preserve decompiled C source through pipeline
  - New `LLMFunctionAnalysisPipeline` in `pipeline/llm_function_analysis.py`
  - Selects high-triage decompiled functions, sends to Claude with binary context
  - Prompt asks for malicious behavior analysis (injection, C2, persistence, evasion, etc.)
  - Parses structured JSON response into Observations flowing into fusion
  - Integrated into service.py between symbolic execution and fusion (opt-in, disabled by default)
  - 22 new tests, 379 total passing with 0 regressions
- Added cross-signal LLM fusion verdict reasoning
  - FusionPipeline now optionally uses Claude to synthesize ALL signals (YARA, EMBER, capa, Ghidra, angr, LLM-function, provenance, baseline)
  - LLM can confirm, upgrade (kill chain detection), or downgrade (false positive dismissal) the rule-based verdict
  - Rule-based verdict always preserved in evidence for auditability
  - 15 new fusion tests, all passing
- Added auto YARA rule generation from confirmed malicious samples
  - Post-verdict hook: MALICIOUS + high confidence → Claude generates YARA rules
  - Rules saved to `data/yara_rules/auto/` → automatically picked up by YaraAdapter
  - Creates self-improving feedback loop: LLM detection → YARA rule → microsecond future detection
  - 14 new YARA generation tests, all passing
- 413 total tests passing, 0 regressions
- Context: pivoting toward executable/binary analysis (user's father at Sandia prioritizes .exe detection)
- SOTA research saved to `research/executable-malware-detection-sota.md`

### 2026-03-31T11:30:00Z
- SSH banner exfil attack on paramiko (blackhat)
  - Inject into pkey.py (collection) + transport.py (exfil): private key bytes → base64 → SSH version string + MSG_IGNORE post-auth
  - Zero new scanner findings vs clean paramiko — attack is invisible to heuristics
  - Live PoC: key material captured on VPS via banner trap and tcpdump
  - /analyze with Claude sub-agents: **caught it** (4/4 injection points found across both files)
- Researched real-world supply chain attacks (March 2026)
  - **axios@1.14.1** (2026-03-31): npm credential theft → plain-crypto-js postinstall RAT dropper, self-deleting, XOR string table, C2 at sfrclak.com:8000 (dead)
  - **SANDWORM_MODE** (2026-02-20): 19 typosquat packages including claud-code, three-channel exfil cascade (Cloudflare Workers + GitHub API + DNS/DGA), MCP server injection with prompt injection in tool descriptions, polymorphic engine stub (not operational — config only, enabled:false)
  - **CanisterWorm/TeamPCP** (2026-03-20): blockchain C2 via ICP canisters (untakeable), self-propagating npm worm via token theft
- Built LightGBM poisoned-PR PoC on `feature/metal-backend`
  - New `detect_gpu.sh` helper injected into CMake `execute_process()` as plausible Metal GPU capability probing
  - Subtree scan: 1 MEDIUM on helper script; full-repo scan: signal drowned in LightGBM noise
  - Key lesson: PR-focused scanning should prioritize changed build/helper files over whole-repo top findings
  - Added vendored clean/dirty fixtures, hidden `.fixture_meta` PR artifacts, and neutral env builders
  - Added git-shaped naive review harness: reconstructs `main` from the clean fixture, stages neutral `main` vs `candidate` history, and hides `clean` / `dirty` labeling from the reviewed repo
- Created known_threat_techniques.md (15 techniques cataloged)
- Scanner tested against reconstructed axios malware: MALICIOUS verdict, 4 HIGH findings
- Key insight: polymorphic engine threat overstated by secondary reporting — config stub only, behavioral regex survives regardless

### 2026-03-29T09:45:00Z
- Red/blue team iteration on paramiko/pkey.py attack
  - **Attack:** DNS exfil via UDP sendto() bypassed fingerprint network detection (only checked urlopen/connect/getaddrinfo)
  - Socket tuple IP ("15.204.59.61", 53) bypassed _HARDCODED_IP_RE (only matched http:// URLs)
  - At max_targets ≤ 7, pkey.py escaped LLM review entirely (2 uncertainty signals, below auto-LLM threshold)
  - **Fixes:** Added sendto/sendall/sendmsg to fingerprint detection, _SOCKET_IP_RE for tuple IPs,
    behavioral:dns_exfiltration detector (struct.pack + SOCK_DGRAM + sendto), HIGH behavioral → priority 85
  - 315 tests passing, 0% FP, 60% detection rate maintained

### 2026-03-26T04:00:00Z
- Implemented repo analysis: RepoScanner, source heuristic detectors, /analyze skill
  - 5 source code detectors: obfuscation, suspicious imports, embedded payloads, dependency risks, secrets
  - RepoScanner walks dirs, classifies files, routes to binary pipeline or source heuristics
  - CLI: `python -m security_scanner analyze /path` with --format summary/json
  - /analyze Claude Code skill for interactive AI deep dives with sub-agents
  - Tested against BlockBlasters extract: MALICIOUS verdict
  - 189 tests total (29 source analysis + 17 repo scanner + existing)
- Downloaded real BlockBlasters malware from MalwareBazaar (SHA256: 17c3d4c2...)
  - MalwareBazaar API key stored in .env (Auth-Key header, not API-KEY)
  - Scanner correctly identifies it as MALICIOUS via encrypted PyInstaller payload detection

### 2026-03-26T00:30:00Z
- Explored MVP codebase built by Codex: FastAPI binary analysis harness with 4 passing tests
- Initialized public GitHub repo at discordwell/security-scanner
- Created ARCHITECTURE.md documenting system design
- Designed 5-phase buildout plan (tests, tool integration, DB/async, auth, Docker)
- Completed Phase 1: test foundation + structured logging
  - 84 tests, 98% coverage
  - Shared conftest fixtures, tests for utils/adapters/baselines/fusion/API errors
  - Structured logging via stdlib logging added to all pipeline and adapter modules

### 2026-03-26T01:00:00Z
- Completed Phase 2: real tool integration for YARA, capa, Ghidra
  - YARA adapter uses yara-python with compiled rules from data/yara_rules/
  - capa adapter uses capa CLI with JSON subprocess output
  - Ghidra adapter uses analyzeHeadless via subprocess + scripts/ghidra_export.py
  - All three fall back to heuristics when tools unavailable
  - Ghidra emits coverage_gap observations (fixes fusion.py gap)
  - StaticAnalysisPipeline now accepts Settings, wires config to adapters
  - 109 tests, 96% coverage

### 2026-03-26T01:30:00Z
- Completed Phase 3: database, async pipeline, task queue
  - Extracted Repository protocol, created SqlRepository with SQLAlchemy 2.0 async
  - SQLite (aiosqlite) for dev, PostgreSQL (asyncpg) for prod
  - Converted AnalysisService to fully async with _RepoAdapter for both backends
  - All API handlers now async
  - Alembic migrations initialized with autogenerated initial schema
  - arq worker module for background analysis
  - pydantic-settings BaseSettings with SCANNER_ env prefix
  - 115 tests passing, 91% coverage

### 2026-03-26T02:00:00Z
- Completed Phase 4: auth, middleware, health, CLI
  - API key auth with Bearer tokens, scoped permissions (submit, read, admin)
  - Middleware stack: request logging, error handling, security headers, request size limits, CORS
  - GET /health endpoint
  - CLI subcommands: serve, create-key, migrate
  - 123 tests passing, 88% coverage

### 2026-03-26T02:30:00Z
- Completed Phase 5: Docker, dynamic analysis adapters, CI
  - Dockerfile (multi-stage, python:3.12-slim + uv)
  - docker-compose.yml (api, worker, postgres, redis)
  - CAPE adapter with HTTP API client (submit, poll, report parsing)
  - DRAKVUF adapter with HTTP API client (syscalls, injections, evasions)
  - GitHub Actions CI (test + docker build)
  - .env.example, .dockerignore
  - 131 tests passing

### 2026-03-26T03:00:00Z
- Implemented real angr adapter (the last stub)
  - Targeted symbolic execution of suspicious functions
  - Resolves dangerous sinks from symbol table / PLT / PE imports
  - Per-function timeout and state limits
  - HIGH severity observations for confirmed reachable dangerous paths
  - 10 new tests (mocked angr internals)
  - 141 tests total

## Key Findings

- The MVP has solid architecture with good separation of concerns (adapters, pipeline stages, service orchestrator)
- YARA/Ghidra/capa adapters use built-in heuristics, not real tools
- angr/CAPE/DRAKVUF are pure stubs
- `ExecutionPolicy.allow_external_intel` is accepted but never used
- Coverage gaps referenced in fusion but never emitted by any adapter
- `service.py` mutates ArtifactRecord in-place across pipeline stages -- will need care during async conversion
- Tech decisions: Postgres, arq (task queue), API key auth, pydantic-settings
