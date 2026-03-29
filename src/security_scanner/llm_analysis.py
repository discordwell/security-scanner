"""LLM-powered deep analysis: activation logic, prompt templates, response parsing."""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import Observation, ObservationSeverity, RepoFileRecord
from .reference_graph import ReferenceGraph

logger = logging.getLogger(__name__)

# --- Prompt Templates ---

SUSPICIOUS_SOURCE_PROMPT = """You are a malware analyst. A security scanner flagged this file.

File: {path}
Scanner findings:
{findings}

Your task: Read this code and determine what it actually DOES when executed.

1. Is there a legitimate reason for the flagged patterns? (e.g., crypto library, test fixture, build tool)
2. If you find encoded/encrypted content, decode it and report what it contains.
3. Does this code communicate with external servers? If so, what does it send/receive?
4. Does this code access sensitive data (credentials, keys, cookies, wallets)?
5. Does this code achieve persistence (startup items, cron, registry)?
6. Are there indirect function calls designed to evade static analysis? (getattr, globals(), string concatenation to build function names)

=== File Content ===
{content}

Respond with your analysis, then end with a JSON block:
```json
{{"verdict": "benign|suspicious|malicious", "confidence": 0.0, "summary": "one sentence", "findings": [{{"severity": "medium|high|critical", "category": "...", "message": "..."}}], "iocs": []}}
```"""

CROSS_FILE_PROMPT = """You are a malware analyst investigating a potential split-payload attack.

The scanner identified a cross-file data flow:
- Data file: {data_file} contains: {data_indicators}
- Exec file: {exec_file} contains: {exec_indicators}
- Connection: {connection}

Your task: Trace the data flow between these files.
1. Does the encoded data from the data file get executed by the exec file?
2. Is this a split payload attack, or a legitimate pattern? (template rendering, config loading, test data)
3. If the data is encoded, decode it. What does the decoded content do?

=== Data File: {data_file} ===
{data_content}

=== Exec File: {exec_file} ===
{exec_content}

Respond with your analysis, then end with a JSON block:
```json
{{"verdict": "benign|suspicious|malicious", "confidence": 0.0, "summary": "one sentence", "findings": [{{"severity": "medium|high|critical", "category": "...", "message": "..."}}], "iocs": []}}
```"""

ENTRY_POINT_PROMPT = """You are a malware analyst reviewing a package entry point.

File: {path}
Install command: {install_command}
Scanner findings:
{findings}

Flagged files in this package:
{flagged_files}

Your task: Determine what happens when a user installs/runs this package.
1. What code executes during installation?
2. Does it download anything from external sources?
3. Does it execute any code from other files in this package?
4. Does it access the filesystem, network, or environment in unexpected ways?
5. Are there install hooks (preinstall, postinstall, cmdclass) that run code?

=== File Content ===
{content}

Respond with your analysis, then end with a JSON block:
```json
{{"verdict": "benign|suspicious|malicious", "confidence": 0.0, "summary": "one sentence", "findings": [{{"severity": "medium|high|critical", "category": "...", "message": "..."}}], "iocs": []}}
```"""

BUILD_FILE_PROMPT = """You are a malware analyst reviewing a build/CI configuration file.

File: {path}
Scanner findings:
{findings}

Your task: Determine if this build file contains malicious commands.
1. Does it download and execute external scripts (curl|bash, wget, etc.)?
2. Does it access credentials or secrets in unexpected ways?
3. Does it modify the build output or inject code?
4. Are there any commands that look out of place for a build file?

=== File Content ===
{content}

Respond with your analysis, then end with a JSON block:
```json
{{"verdict": "benign|suspicious|malicious", "confidence": 0.0, "summary": "one sentence", "findings": [{{"severity": "medium|high|critical", "category": "...", "message": "..."}}], "iocs": []}}
```"""

TRIAGE_PROMPT = """You are a malware analyst triaging automated scanner findings for a large repository.

Project type: {project_type}
Repository: {file_count} files scanned
Normal patterns for this project type: {normal_patterns}

The scanner produced {finding_count} alerts. Most are likely legitimate for this project type.
Your job: identify which findings are GENUINELY SUSPICIOUS vs normal for this project.

Key principle: even in a {project_type} project, a file that reads ~/.ssh/id_rsa, ~/.aws/credentials,
or ~/.npmrc AND sends data to an external server is suspicious. That's credential theft, not normal
library behavior.

=== HIGH/CRITICAL Findings ({high_count}) ===
{high_findings}

=== MEDIUM Findings with behavioral patterns ===
{behavioral_findings}

=== Other MEDIUM Findings ({other_medium_count}) ===
{other_medium_findings}

Respond with a JSON block listing ONLY the genuinely suspicious files:
```json
{{"suspicious_files": ["path/to/file.py"], "reasoning": "Brief explanation.", "dismissed_count": 0}}
```"""


def infer_project_type(files: list, graph) -> tuple[str, str]:
    """Infer project type and what patterns are normal for it."""
    paths = " ".join(f.path.lower() for f in files)

    if any(kw in paths for kw in ("ssh", "sftp", "transport", "kex_")):
        return "SSH/crypto library", "hex protocol constants, socket imports, key handling, base64 encoding"
    if any(kw in paths for kw in ("cipher", "ecdsa", "ed25519", "rsa", "x509")):
        return "cryptography library", "hex constants, base64, binary protocol data, key serialization"
    if any(kw in paths for kw in ("node_modules", "webpack", "babel")):
        return "Node.js project", "require() calls, npm scripts, build tooling"
    if "package.json" in paths:
        return "npm package", "JavaScript modules, npm lifecycle scripts"
    if any(kw in paths for kw in ("django", "flask", "fastapi")):
        return "Python web framework", "template rendering, config loading, middleware"
    if "setup.py" in paths or "pyproject.toml" in paths:
        return "Python package", "setup.py configuration, module imports"

    return "software project", "standard library imports and configuration"


def build_triage_prompt(files: list, graph) -> str:
    """Build a triage prompt summarizing all findings (no file contents)."""
    from .reference_graph import ReferenceGraph
    project_type, normal_patterns = infer_project_type(files, graph)

    high_findings = []
    behavioral_findings = []
    other_medium = []

    for f in files:
        for o in f.observations:
            entry = f"  [{o.severity.value.upper():8s}] {f.path}: {o.category} -- {o.message[:100]}"
            if o.severity.value in ("high", "critical"):
                high_findings.append(entry)
            elif "behavioral" in o.category:
                behavioral_findings.append(entry)
            elif o.severity.value == "medium":
                other_medium.append(entry)

    return TRIAGE_PROMPT.format(
        project_type=project_type,
        file_count=len(files),
        finding_count=len(high_findings) + len(behavioral_findings) + len(other_medium),
        normal_patterns=normal_patterns,
        high_count=len(high_findings),
        high_findings="\n".join(high_findings[:50]) or "(none)",
        behavioral_findings="\n".join(behavioral_findings[:20]) or "(none)",
        other_medium_count=len(other_medium),
        other_medium_findings="\n".join(other_medium[:30]) or "(none -- showing max 30)",
    )


def parse_triage_response(response_text: str) -> list[str]:
    """Extract the list of suspicious file paths from triage response."""
    match = _JSON_BLOCK_RE.search(response_text)
    if not match:
        logger.warning("No JSON block in triage response")
        return []
    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse triage JSON: %s", exc)
        return []
    suspicious = data.get("suspicious_files", [])
    return [str(s) for s in suspicious] if isinstance(suspicious, list) else []


# --- Data types ---

@dataclass(slots=True)
class AnalysisTarget:
    path: str
    prompt_type: str  # "suspicious_source", "cross_file", "entry_point", "build_file"
    priority: int
    context: dict  # Varies by prompt_type


@dataclass(slots=True)
class LLMAnalysisResult:
    observations: list[Observation] = field(default_factory=list)
    files_analyzed: int = 0
    files_skipped: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    targets_selected: int = 0
    adapter_available: bool = False
    triage_mode: bool = False
    triage_suspicious_files: list[str] = field(default_factory=list)


# --- Response parsing ---

_JSON_BLOCK_RE = re.compile(r'```json\s*\n(.*?)\n\s*```', re.DOTALL)

SEVERITY_MAP = {
    "medium": ObservationSeverity.MEDIUM,
    "high": ObservationSeverity.HIGH,
    "critical": ObservationSeverity.CRITICAL,
}


def parse_llm_response(response_text: str, path: str) -> list[Observation]:
    """Extract structured findings from LLM response JSON block."""
    match = _JSON_BLOCK_RE.search(response_text)
    if not match:
        logger.warning("No JSON block found in LLM response for %s", path)
        return []

    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse LLM JSON for %s: %s", path, exc)
        return []

    observations: list[Observation] = []
    confidence = float(data.get("confidence", 0.5))
    verdict = data.get("verdict", "suspicious")
    summary = data.get("summary", "")
    iocs = data.get("iocs", [])

    # Verdict-level observation
    if verdict == "malicious" and confidence >= 0.7:
        observations.append(Observation(
            source="llm-analysis",
            category="llm:malicious_confirmed",
            severity=ObservationSeverity.HIGH,
            message=f"LLM analysis ({confidence:.0%} confidence): {summary}",
            evidence={"path": path, "confidence": confidence, "verdict": verdict, "iocs": iocs},
            tags=["llm", "confirmed"],
        ))
    elif verdict == "benign":
        observations.append(Observation(
            source="llm-analysis",
            category="llm:benign_confirmed",
            severity=ObservationSeverity.INFO,
            message=f"LLM assessment ({confidence:.0%} confidence): likely benign. {summary}",
            evidence={"path": path, "confidence": confidence, "verdict": verdict},
            tags=["llm", "benign", "advisory"],
        ))

    # Individual findings
    for finding in data.get("findings", []):
        sev = SEVERITY_MAP.get(finding.get("severity", "medium"), ObservationSeverity.MEDIUM)
        obs = Observation(
            source="llm-analysis",
            category=finding.get("category", "llm:finding"),
            severity=sev,
            message=finding.get("message", "LLM finding"),
            evidence={"path": path, "confidence": confidence},
            tags=["llm"] + (["advisory"] if confidence < 0.7 else []),
        )
        observations.append(obs)

    return observations


# --- Target selection ---

def select_targets(
    files: list[RepoFileRecord],
    graph: ReferenceGraph,
    max_targets: int = 10,
    triage_suspicious: list[str] | None = None,
) -> list[AnalysisTarget]:
    """Select files for LLM analysis, prioritized by suspicion level."""
    targets: dict[str, AnalysisTarget] = {}

    entry_set = set(graph.entry_points)
    manifest_set = set(graph.manifests)
    build_set = set(graph.build_files)

    def _add(path: str, prompt_type: str, priority: int, context: dict):
        if path in targets:
            if priority > targets[path].priority:
                targets[path] = AnalysisTarget(path, prompt_type, priority, context)
        else:
            targets[path] = AnalysisTarget(path, prompt_type, priority, context)

    # Priority 110: Triage-selected suspicious files (LLM already identified these)
    if triage_suspicious:
        file_by_path = {f.path: f for f in files}
        for path in triage_suspicious:
            f = file_by_path.get(path)
            if f:
                findings_summary = "; ".join(f"{o.severity.value}: {o.message[:80]}" for o in f.observations[:5])
                _add(path, "suspicious_source", 110, {"findings": findings_summary, "triage_selected": True})

    # Priority 100: Cross-file leads
    for lead in graph.leads:
        _add(lead.exec_file, "cross_file", 100, {
            "lead": {
                "data_file": lead.data_file,
                "exec_file": lead.exec_file,
                "connection": lead.connection,
                "data_indicators": lead.data_indicators,
                "exec_indicators": lead.exec_indicators,
            }
        })

    for f in files:
        if not f.observations:
            continue

        has_high = any(o.severity.value in ("high", "critical") for o in f.observations)
        has_medium = any(o.severity.value == "medium" for o in f.observations)
        indicator_count = len(f.observations)
        findings_summary = "; ".join(f"{o.severity.value}: {o.message[:80]}" for o in f.observations[:5])

        # Priority 90: Entry points with HIGH+ findings
        if f.path in entry_set and has_high:
            install_cmd = "pip install ." if f.path.endswith(".py") else "npm install"
            _add(f.path, "entry_point", 90, {
                "findings": findings_summary,
                "install_command": install_cmd,
            })
        # Priority 80: Entry points with ANY findings
        elif f.path in entry_set:
            install_cmd = "pip install ." if f.path.endswith(".py") else "npm install"
            _add(f.path, "entry_point", 80, {
                "findings": findings_summary,
                "install_command": install_cmd,
            })
        # Priority 70: Manifests with findings
        elif f.path in manifest_set:
            _add(f.path, "entry_point", 70, {
                "findings": findings_summary,
                "install_command": "pip install" if "requirements" in f.path else "npm install",
            })
        # Priority 60: Build/CI files with findings
        elif f.path in build_set:
            _add(f.path, "build_file", 60, {"findings": findings_summary})
        # Priority 65: Migration files with findings (run during manage.py migrate)
        elif "/migrations/" in f.path and f.path.endswith(".py") and has_medium:
            _add(f.path, "suspicious_source", 65, {"findings": findings_summary})
        # Priority 55: Behavioral credential theft (single finding is enough -- this is high signal)
        elif any(o.category.startswith("behavioral:credential_access") for o in f.observations):
            _add(f.path, "suspicious_source", 55, {"findings": findings_summary})
        # Priority 50: Any file with MEDIUM+ and 2+ indicators
        elif has_medium and indicator_count >= 2:
            _add(f.path, "suspicious_source", 50, {"findings": findings_summary})

    # Sort by priority descending, cap at max
    sorted_targets = sorted(targets.values(), key=lambda t: t.priority, reverse=True)
    return sorted_targets[:max_targets]


# --- Prompt construction ---

def build_prompt(target: AnalysisTarget, repo_path: Path) -> str:
    """Build the LLM prompt for a given analysis target."""
    try:
        content = (repo_path / target.path).read_text(errors="replace")[:50000]
    except OSError:
        content = "(file not readable)"

    findings = target.context.get("findings", "No specific findings.")

    if target.prompt_type == "cross_file":
        lead = target.context.get("lead", {})
        try:
            data_content = (repo_path / lead["data_file"]).read_text(errors="replace")[:30000]
        except (OSError, KeyError):
            data_content = "(not readable)"
        try:
            exec_content = (repo_path / lead["exec_file"]).read_text(errors="replace")[:30000]
        except (OSError, KeyError):
            exec_content = "(not readable)"
        return CROSS_FILE_PROMPT.format(
            data_file=lead.get("data_file", "?"),
            exec_file=lead.get("exec_file", "?"),
            data_indicators=", ".join(lead.get("data_indicators", [])),
            exec_indicators=", ".join(lead.get("exec_indicators", [])),
            connection=lead.get("connection", "unknown"),
            data_content=data_content,
            exec_content=exec_content,
        )

    if target.prompt_type == "entry_point":
        flagged = [f for f in (repo_path).rglob("*") if f.is_file()][:10]  # simplified
        return ENTRY_POINT_PROMPT.format(
            path=target.path,
            install_command=target.context.get("install_command", "install"),
            findings=findings,
            flagged_files="(see scanner report for full list)",
            content=content,
        )

    if target.prompt_type == "build_file":
        return BUILD_FILE_PROMPT.format(path=target.path, findings=findings, content=content)

    # Default: suspicious source
    return SUSPICIOUS_SOURCE_PROMPT.format(path=target.path, findings=findings, content=content)


# --- Orchestrator ---

class LLMAnalysisPhase:
    def __init__(self, settings=None, adapter=None):
        self._settings = settings
        self._adapter = adapter
        self._max_files = getattr(settings, "llm_max_files_per_scan", 10) if settings else 10
        self._budget = getattr(settings, "llm_budget_tokens", 100_000) if settings else 100_000
        self._triage_threshold = getattr(settings, "llm_triage_threshold", 20) if settings else 20

    async def analyze(
        self,
        files: list[RepoFileRecord],
        graph: ReferenceGraph,
        repo_path: Path,
    ) -> LLMAnalysisResult:
        if not self._adapter:
            targets = select_targets(files, graph, max_targets=self._max_files)
            return LLMAnalysisResult(
                targets_selected=len(targets),
                adapter_available=False,
            )

        # Count findings to decide mode
        finding_count = sum(
            1 for f in files for o in f.observations
            if o.severity.value in ("high", "critical", "medium")
        )
        finding_count += len(graph.leads)

        if finding_count > self._triage_threshold:
            return await self._analyze_with_triage(files, graph, repo_path)
        return await self._analyze_direct(files, graph, repo_path)

    async def _analyze_direct(
        self,
        files: list[RepoFileRecord],
        graph: ReferenceGraph,
        repo_path: Path,
    ) -> LLMAnalysisResult:
        """Standard mode: deep-dive top N files."""
        targets = select_targets(files, graph, max_targets=self._max_files)
        result = LLMAnalysisResult(
            targets_selected=len(targets),
            adapter_available=True,
        )

        if not targets:
            return result

        remaining_budget = self._budget
        for target in targets:
            if remaining_budget <= 0:
                result.files_skipped += 1
                continue
            prompt = build_prompt(target, repo_path)
            try:
                response_text, in_tokens, out_tokens = await self._adapter.analyze_file(
                    prompt=prompt, remaining_budget=remaining_budget,
                )
                remaining_budget -= (in_tokens + out_tokens)
                result.total_input_tokens += in_tokens
                result.total_output_tokens += out_tokens
                if response_text:
                    result.observations.extend(parse_llm_response(response_text, target.path))
                    result.files_analyzed += 1
                else:
                    result.files_skipped += 1
            except Exception as exc:
                logger.warning("LLM analysis failed for %s: %s", target.path, exc)
                result.files_skipped += 1

        logger.info("LLM direct: %d targets, %d analyzed, %d observations",
                    result.targets_selected, result.files_analyzed, len(result.observations))
        return result

    async def _analyze_with_triage(
        self,
        files: list[RepoFileRecord],
        graph: ReferenceGraph,
        repo_path: Path,
    ) -> LLMAnalysisResult:
        """Triage mode: batch-classify all findings, then deep-dive only genuinely suspicious files."""
        result = LLMAnalysisResult(adapter_available=True, triage_mode=True)

        # Pass 1: Triage (cheap -- finding summaries, no file contents)
        triage_prompt = build_triage_prompt(files, graph)
        triage_budget = getattr(self._settings, "llm_triage_budget_tokens", 15_000) if self._settings else 15_000

        try:
            response_text, in_tokens, out_tokens = await self._adapter.analyze_file(
                prompt=triage_prompt, remaining_budget=triage_budget,
            )
            result.total_input_tokens += in_tokens
            result.total_output_tokens += out_tokens
        except Exception as exc:
            logger.warning("Triage LLM call failed: %s -- falling back to direct mode", exc)
            return await self._analyze_direct(files, graph, repo_path)

        if not response_text:
            return await self._analyze_direct(files, graph, repo_path)

        suspicious_paths = parse_triage_response(response_text)
        result.triage_suspicious_files = suspicious_paths
        logger.info("Triage identified %d suspicious files: %s", len(suspicious_paths), suspicious_paths)

        result.observations.append(Observation(
            source="llm-triage",
            category="llm:triage_complete",
            severity=ObservationSeverity.INFO,
            message=f"LLM triage analyzed all findings, identified {len(suspicious_paths)} suspicious files.",
            evidence={"suspicious_files": suspicious_paths},
            tags=["llm", "triage"],
        ))

        # Pass 2: Deep-dive only the suspicious files
        max_deep_dive = getattr(self._settings, "llm_triage_max_deep_dive", 5) if self._settings else 5
        remaining_budget = self._budget - result.total_input_tokens - result.total_output_tokens
        file_by_path = {f.path: f for f in files}

        for path in suspicious_paths[:max_deep_dive]:
            if remaining_budget <= 0:
                result.files_skipped += 1
                continue
            f = file_by_path.get(path)
            findings_summary = "; ".join(f"{o.severity.value}: {o.message[:80]}" for o in f.observations[:5]) if f else ""
            target = AnalysisTarget(path, "suspicious_source", 110, {
                "findings": findings_summary, "triage_selected": True,
            })
            prompt = build_prompt(target, repo_path)
            try:
                response_text, in_tokens, out_tokens = await self._adapter.analyze_file(
                    prompt=prompt, remaining_budget=remaining_budget,
                )
                remaining_budget -= (in_tokens + out_tokens)
                result.total_input_tokens += in_tokens
                result.total_output_tokens += out_tokens
                if response_text:
                    result.observations.extend(parse_llm_response(response_text, path))
                    result.files_analyzed += 1
                else:
                    result.files_skipped += 1
            except Exception as exc:
                logger.warning("Deep-dive failed for %s: %s", path, exc)
                result.files_skipped += 1

        result.targets_selected = len(suspicious_paths)
        logger.info("LLM triage: %d suspicious, %d deep-dived, %d observations",
                    len(suspicious_paths), result.files_analyzed, len(result.observations))
        return result
