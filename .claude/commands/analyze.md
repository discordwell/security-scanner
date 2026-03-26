# Security Analysis: Deep Dive

Perform a comprehensive security analysis of a repository or directory, combining automated scanning with AI-powered code review.

## Arguments
$ARGUMENTS - Path to the repository or directory to analyze

## Workflow

### Phase 1: Automated Scan

Run the scanner's automated heuristics against the target:

```bash
uv run python -m security_scanner analyze $ARGUMENTS --output /tmp/scanner-report.json --format json
```

Also produce a human-readable summary:
```bash
uv run python -m security_scanner analyze $ARGUMENTS --format summary
```

Read `/tmp/scanner-report.json` and note:
- The aggregate verdict (CLEAN/SUSPICIOUS/MALICIOUS)
- Total file count and breakdown by classification
- All HIGH and CRITICAL severity findings
- All MEDIUM findings grouped by category

### Phase 2: AI Triage

Based on the automated report, identify the files that need manual review. Prioritize:

1. Files with HIGH/CRITICAL observations
2. Binary files with MALICIOUS/SUSPICIOUS verdicts
3. Files with multiple MEDIUM observations
4. Dependency manifests (package.json, requirements.txt, setup.py, go.mod)
5. Entry points (main.py, index.js, setup.py, __init__.py)
6. Any file with obfuscation indicators

### Phase 3: Deep Dive (Sub-Agents)

For each suspicious file identified in Phase 2, spawn an Explore sub-agent to analyze it. Give each agent a focused task:

**For obfuscated code:**
- Read the file
- Attempt to decode any base64/hex/packed content
- Trace what the decoded payload does
- Identify C2 servers, exfiltration targets, persistence mechanisms

**For suspicious binaries (after extraction):**
- Check strings output for wallet addresses, URLs, credential paths
- Map the attack chain: dropper -> payload -> exfiltration

**For dependency manifests:**
- Check every dependency name against known legitimate packages
- Flag any with post-install hooks
- Look for version pinning to known-vulnerable versions

**For entry points and scripts:**
- Trace the execution flow from entry point
- Identify what gets executed, downloaded, or exfiltrated
- Look for anti-analysis checks (debugger detection, VM detection, sleep timers)

Run up to 3 sub-agents in parallel for efficiency.

### Phase 4: Kill Chain Reconstruction

If the verdict is SUSPICIOUS or MALICIOUS, reconstruct the attack chain:

1. **Initial Access**: How does the malware get executed? (game launcher, npm install hook, Python import)
2. **Execution**: What runs first? What gets unpacked/decoded?
3. **Collection**: What data does it target? (browser cookies, crypto wallets, SSH keys, tokens)
4. **Exfiltration**: Where does stolen data go? (C2 server, Telegram bot, Discord webhook)
5. **Persistence**: Does it install anything permanent? (registry keys, cron jobs, startup items)

### Phase 5: Final Report

Produce a structured assessment:

**Verdict**: CLEAN / SUSPICIOUS / MALICIOUS (with confidence: LOW/MEDIUM/HIGH)

**Executive Summary**: 2-3 sentences describing what this repo is and what it does.

**Risk Assessment**:
- What the automated scanner found (counts by severity)
- What the AI deep dive revealed
- Key IOCs (IPs, domains, wallet addresses, file hashes)

**Evidence Table**: For each finding:
| File | Line | Severity | Finding | Explanation |
|------|------|----------|---------|-------------|

**Kill Chain** (if malicious): Step-by-step attack flow with file references.

**Recommendations**: Specific actions (block hash, report to platform, notify affected users, etc.)
