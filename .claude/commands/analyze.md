# Security Analysis: Deep Dive

Perform a comprehensive security analysis combining automated scanning with AI-powered code review.

## Arguments
$ARGUMENTS - Path to the repository or directory to analyze

## Phase 1: Automated Scan

Run the scanner (LLM analysis disabled -- YOU are the LLM layer):

```bash
uv run python -m security_scanner analyze $ARGUMENTS --no-llm --output /tmp/scanner-report.json --format json
```

Also get a quick summary:
```bash
uv run python -m security_scanner analyze $ARGUMENTS --no-llm --format summary
```

Read `/tmp/scanner-report.json`. Note:
- `aggregate_verdict` (CLEAN/SUSPICIOUS/MALICIOUS)
- `statistics` (file counts, finding counts)
- `top_findings` (highest severity observations)
- `cross_file_leads` (data→exec flows detected between files)
- `llm_analysis_targets` (prioritized list of files needing deep analysis)

## Phase 2: AI Triage

Read `llm_analysis_targets` from the report. Each entry has:
- `path`: File to analyze
- `prompt_type`: Analysis approach ("suspicious_source", "cross_file", "entry_point", "build_file")
- `priority`: Numeric score (100=cross-file lead, 90=entry point with HIGH, etc.)
- `context`: Why this was selected + regex findings

Also read `cross_file_leads` -- these are data→exec flow patterns where encoded data in one file is reachable from exec-capable code in another.

If both are empty and verdict is CLEAN, skip to Phase 5.

## Phase 3: Deep Dive (Sub-Agents)

For the top targets (up to 5), spawn sub-agents in parallel based on `prompt_type`:

**For "suspicious_source":**
Read the file. The scanner found [context.findings]. Determine what this code actually DOES when executed. Decode any encoded/encrypted content. Is there a legitimate reason for the flagged patterns? Look for indirect function calls (getattr, globals()['exec']), string-constructed function names, split variables that reassemble to dangerous operations. Report: what the code does, whether it's malicious, IOCs.

**For "cross_file":**
Read both files named in context.lead. Trace the data flow: does encoded data from the data_file get decoded and executed by the exec_file? Is this a split payload attack or a legitimate pattern (config loading, template rendering, test data)?

**For "entry_point":**
This is setup.py/package.json/etc. What happens when a user runs pip install/npm install? Does it execute code during installation? Does it download anything? Does it reference any files the scanner flagged?

**For "build_file":**
Does this Dockerfile/CI config download and execute external scripts? Does it access secrets unexpectedly? Are there curl|bash patterns?

## Phase 4: Kill Chain Reconstruction

If findings suggest SUSPICIOUS or MALICIOUS, reconstruct:

1. **Initial Access**: How does the malware execute? (pip install hook, npm preinstall, import)
2. **Execution**: What runs first? What gets decoded/decrypted?
3. **Collection**: What data is targeted? (browser cookies, crypto wallets, SSH keys, tokens)
4. **Exfiltration**: Where does stolen data go? (C2 server, Telegram, Discord webhook, blockchain)
5. **Persistence**: Anything permanent? (registry, cron, startup items, ~/init.json)

## Phase 5: Final Report

**Verdict**: CLEAN / SUSPICIOUS / MALICIOUS (confidence: LOW/MEDIUM/HIGH)

**Executive Summary**: 2-3 sentences.

**Risk Assessment**:
- Automated scanner findings (counts by severity)
- AI deep dive findings
- Cross-file leads detected
- Key IOCs (IPs, domains, wallet addresses, hashes)

**Evidence Table**:
| File | Line | Severity | Finding | Explanation |
|------|------|----------|---------|-------------|

**Kill Chain** (if malicious): Step-by-step attack flow.

**Recommendations**: Block hash, report to platform, notify users, etc.
