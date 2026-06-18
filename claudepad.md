# Claudepad

## Session Summaries

### 2026-06-18T00:00:00Z
- **Closed setup.py install-hook detection gap (pkg_dataprocessor: SUSPICIOUS → MALICIOUS)**
  - Root cause: a `setup.py` that steals credentials + exfiltrates only produced a single MEDIUM
    (`behavioral:credential_access_exfil`) → SUSPICIOUS. But setup.py runs on `pip install` before any
    user code, so install-time credential theft is the canonical PyPI supply-chain attack and is MALICIOUS.
  - Fix 1: `detect_behavioral_patterns` now elevates credential+exfil to **HIGH**
    `behavioral:install_hook_credential_exfil` when the file is an install script (`setup.py`). Same
    pattern in an ordinary module stays MEDIUM (only runs if the victim calls it).
  - Fix 2: new `detect_install_hooks` detector flags setup.py **droppers** → HIGH `supply_chain:install_dropper`:
    `curl|wget ... | sh/bash/python/node/...` (curl-pipe-interpreter) OR remote-fetch
    (urlopen/urlretrieve/requests|httpx .get/.post) + in-process `exec`/`eval`.
  - FP guards (from code review): the fetch-pairing is limited to in-process exec/eval — a benign
    `urlretrieve(...) ; os.system('tar xzf ...')` (download-then-unpack) and list-form
    `subprocess.check_call(['cmake',...])` (native build) do NOT fire. `compile()` excluded (builds a
    code object, isn't execution). Verified FP=0 on clean cases (pkg_makefile_app, pkg_flask_hello, etc.).
  - Removed dead `dependency:custom_install` branch (it lived in `detect_dependency_risks`, only called for
    CONFIG files, but setup.py is SOURCE → never reached; bare-cmdclass MEDIUM would also over-flag legit
    native-build packages). Behavior-based detectors replace it.
- **Fixed `from . import X` / `from .. import X` reference-graph bug** (cross-file split-payload analysis)
  - `_parse_references` picked the `from` part ("." for a bare relative import) as the edge target, which
    resolves to nothing → the edge was silently dropped. Now preserves the dot prefix (`.` + `helper` →
    `.helper`) so `_resolve_path` walks up the right level and resolves the sibling module. Common idiom;
    previously invisible to the split-payload graph.
- Eval (heuristic-only): **14/17 → 15/17 (79% → 86%)**, FP=0. Remaining 2 FNs are the genuinely-hard
  cross-file (pkg_config_manager, absolute import) and SSH-handshake-piggyback (pkg_ssh_lite) cases.
- 463 tests passing (was 453), 11 skipped, 0 regressions. +10 new tests. Left `research/` untracked
  (deliberate, per prior sessions). Did not touch dormant `anomaly_score_threshold` config (ambiguous
  HIGH-cutoff vs min-report semantics; the only test documents 0.7 — wiring it risks severity regressions).

### 2026-06-17T00:00:00Z
- **Fixed MALICIOUS false-positive on clean compiled-language repos** (eval/exec detector)
  - Root cause: `_EVAL_EXEC_RE = \b(eval|exec)\(` matched method calls/declarations, not just builtins.
    Eigen's `matrix.eval()` / `ReturnType eval() const` (vendored C++) produced 5+ obfuscation MEDIUMs
    that stacked into a MALICIOUS verdict via the compound-attack-chain rule.
  - Fix 1: negative lookbehind `(?<![\w.>:])` rejects member/scope calls (`.eval()`, `->exec()`, `::eval()`)
  - Fix 2: language gate `_eval_exec_is_builtin(path)` skips compiled-lang extensions (C/C++/Rust/Go/Java/...);
    `has_eval_exec` computed once and reused by the CRITICAL/HIGH escalation checks
  - **repo_lightgbm_metal_pr_clean: MALICIOUS → SUSPICIOUS**; bare `eval(payload)` in .py/.js/.php/.rb/.sh still fires
  - 4 new regression tests
- **Refactor: extracted shared compound-attack-chain rule into `verdict_rules.py`** (tracked follow-up)
  - The "3+ MEDIUM across 3+ attack vectors → MALICIOUS" logic + `_NON_ATTACK_PREFIXES` set was duplicated
    in `pipeline/fusion.py` and `repo_scanner.py`; now single-sourced (`attack_vector_categories`,
    `is_compound_attack_chain`, constants). Behavior identical; 7 new unit tests.
- 453 tests passing (was 442), 0 regressions. Eval unchanged: FP=0, same 3 pre-existing FNs.
- Left `research/` untracked (deliberate: public repo, dual-use exfil notes the operator kept local since April).

### 2026-04-20T00:00:00Z
- Comprehensive project audit (4 parallel agents: code quality, scanner security, detection, ops/DX)
- Detection pass implementation (item 2 from audit recommendations)
  - Extended `obfuscation:import_exec_chain` to catch `importlib.import_module` as __import__-equivalent (ForceMemo variants)
  - New `behavioral:git_exfiltration` HIGH detector (subprocess git commit/push + credential-path reads)
  - New `behavioral:migration_credential_theft` HIGH detector (Django `migrations.RunPython` + credential reads)
  - Hex-escape FP fix: demoted to INFO when alone; MEDIUM only with co-occurring obfuscation signals
  - Compound MEDIUM→MALICIOUS fusion rule: 3+ MEDIUMs across 3+ distinct attack-vector prefixes (excluding `unresolved`/`ast`/`coverage_gap`/`llm`). Applied in both `pipeline/fusion.py` and `repo_scanner._aggregate_verdict`
  - Anomaly scoring language gate: scores only `.py/.js/.ts/.jsx/.tsx` files (non-eligible files still counted as peers/baseline so single-script packages still work)
- **Eval: 15/25 → 21/25 (60% → 84%)**, zero regressions in the 429-test unit suite
  - Fixed: pkg_crypto_util (FP), pkg_devtools_sync (git exfil), pkg_django_cache (ForceMemo), pkg_django_profiles (RunPython), pkg_env_validator (compound MED), pkg_string_helpers (compound MED)
  - Still failing: pkg_config_manager (3-file payload split), pkg_dataprocessor (setup.py cmdclass), pkg_ssh_lite (SSH handshake piggyback), repo_lightgbm_metal_pr_clean (string-split FP on Eigen)
- 13 new tests (importlib, hex FP, git exfil, RunPython, compound MED fusion, anomaly gating)
- Follow-ups from code review (tracked; not blocking):
  - Git-exfil detector may FP on dotfile-sync tools that read `~/.gitconfig` and `git push`
  - Compound MEDIUM 3+3 rule could over-escalate legit projects combining postinstall + base64 + bulk credential access
  - Hex-escape MEDIUM/INFO decision is ordering-dependent (future detectors added before it would change severity)
  - Compound-MEDIUM logic duplicated between fusion.py and repo_scanner.py

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
- Added Triage cloud sandbox adapter (hatching.io)
  - Real dynamic analysis without self-hosted infrastructure
  - Submit/poll/report flow with signature, network IOC, config extraction, dropped file parsing
  - Fixed event loop blocking bug: `dynamic.analyze()` now wrapped in `asyncio.to_thread`
  - 9 new adapter tests
- Built binary eval harness (eval/download_samples.py, eval/run_binary_eval.py, eval/metrics.py)
  - Downloads labeled samples from MalwareBazaar API
  - Runs samples through scanner, records verdicts vs ground truth
  - Computes accuracy, precision, recall, F1, confusion matrix
  - 9 new metrics tests
- 431 total tests passing, 0 regressions
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
