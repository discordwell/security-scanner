"""LLM-powered analysis of decompiled binary functions.

Feeds high-triage decompiled C functions to Claude for intent analysis,
producing Observations that flow into the fusion verdict.
"""
from __future__ import annotations

import json
import logging
import re

from ..adapters.anthropic_llm import AnthropicLLMAdapter
from ..adapters.types import AdapterResult
from ..models import (
    ArtifactRecord,
    FunctionSummary,
    Observation,
    ObservationSeverity,
    ToolExecution,
    ToolStatus,
)

logger = logging.getLogger(__name__)

_JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n\s*```", re.DOTALL)

SEVERITY_MAP = {
    "benign": None,
    "low": ObservationSeverity.LOW,
    "medium": ObservationSeverity.MEDIUM,
    "high": ObservationSeverity.HIGH,
    "critical": ObservationSeverity.CRITICAL,
}

SYSTEM_PROMPT = """\
You are a malware analyst reviewing decompiled C code from a binary executable.
Your task is to determine whether each function exhibits malicious behavior.

Focus on:
- Process injection (CreateRemoteThread, WriteProcessMemory, NtMapViewOfSection)
- Shellcode loading (VirtualAlloc + memcpy + CreateThread)
- Persistence mechanisms (registry writes, scheduled tasks, startup folders)
- C2 communication (HTTP/DNS beaconing, encrypted channels, hardcoded IPs)
- Credential theft (LSASS access, keylogging, clipboard monitoring)
- Anti-analysis / evasion (debugger checks, VM detection, sleep-based timing)
- Data exfiltration (file reads + network sends)
- Privilege escalation (token manipulation, UAC bypass)

Respond with a JSON block:

```json
{
  "verdict": "benign" | "suspicious" | "malicious",
  "confidence": 0.0-1.0,
  "summary": "One-sentence description of what the function does",
  "behaviors": ["behavior1", "behavior2"],
  "findings": [
    {
      "severity": "low" | "medium" | "high" | "critical",
      "category": "technique category (e.g., process_injection, c2, persistence)",
      "message": "Specific finding description"
    }
  ]
}
```

Be precise. A function that calls VirtualAlloc for legitimate memory management is not
malicious. Look at the full context: what data flows into the allocation, how the memory
is used afterward, and what the function returns."""


def select_functions(
    functions: list[FunctionSummary],
    min_triage_score: float,
    max_functions: int,
    max_code_length: int,
) -> list[FunctionSummary]:
    """Select decompiled functions eligible for LLM analysis."""
    candidates = [
        f
        for f in functions
        if f.decompiled_code is not None
        and len(f.decompiled_code) > 0
        and len(f.decompiled_code) <= max_code_length
        and f.triage_score >= min_triage_score
    ]
    candidates.sort(key=lambda f: f.triage_score, reverse=True)
    return candidates[:max_functions]


def build_function_prompt(
    function: FunctionSummary,
    artifact: ArtifactRecord,
) -> str:
    """Build a prompt for analyzing a single decompiled function."""
    # Gather context from other observations
    existing_observations = "\n".join(
        f"  - [{obs.severity.value}] {obs.source}: {obs.message}"
        for obs in artifact.observations[:15]
    ) or "  (none yet)"

    # Gather call graph context
    calling = ", ".join(function.evidence.get("calling", [])[:5]) or "unknown"
    called_by = ", ".join(function.evidence.get("called_by", [])[:5]) or "unknown"

    # Strings excerpt for context
    strings_excerpt = "\n".join(f"  {s}" for s in artifact.strings[:20]) or "  (none)"

    return f"""{SYSTEM_PROMPT}

## Binary Context

- **Format**: {artifact.format.value}
- **SHA256**: {artifact.sha256}
- **Size**: {artifact.size:,} bytes

### Extracted strings (sample)
{strings_excerpt}

### Prior observations
{existing_observations}

## Function Under Analysis

- **Symbol**: `{function.symbol}`
- **Address range**: {function.start_address} — {function.end_address}
- **Triage score**: {function.triage_score:.2f}
- **Calls**: {calling}
- **Called by**: {called_by}

### Decompiled C code

```c
{function.decompiled_code}
```

Analyze this function. Is it malicious, suspicious, or benign?"""


def parse_function_response(
    response_text: str,
    function: FunctionSummary,
) -> list[Observation]:
    """Extract Observations from an LLM response about a decompiled function."""
    match = _JSON_BLOCK_RE.search(response_text)
    if not match:
        logger.warning("No JSON block in LLM response for %s", function.symbol)
        return []

    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse LLM JSON for %s: %s", function.symbol, exc)
        return []

    observations: list[Observation] = []
    verdict = data.get("verdict", "suspicious")
    try:
        confidence = float(data.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    summary = data.get("summary", "")
    behaviors = data.get("behaviors", [])

    address = function.start_address

    # Verdict-level observation
    if verdict == "malicious" and confidence >= 0.7:
        observations.append(
            Observation(
                source="llm-function",
                category="llm:function_malicious",
                severity=ObservationSeverity.HIGH,
                message=f"LLM function analysis ({confidence:.0%}): {function.symbol} — {summary}",
                evidence={
                    "symbol": function.symbol,
                    "address": address,
                    "confidence": confidence,
                    "verdict": verdict,
                    "behaviors": behaviors,
                },
                addresses=[address],
                tags=["llm", "function", "confirmed"],
            )
        )
    elif verdict == "malicious":
        # Low-confidence malicious — still worth surfacing as suspicious
        observations.append(
            Observation(
                source="llm-function",
                category="llm:function_suspicious",
                severity=ObservationSeverity.MEDIUM,
                message=f"LLM function analysis ({confidence:.0%}, low confidence): {function.symbol} — {summary}",
                evidence={
                    "symbol": function.symbol,
                    "address": address,
                    "confidence": confidence,
                    "verdict": verdict,
                    "behaviors": behaviors,
                },
                addresses=[address],
                tags=["llm", "function", "low_confidence"],
            )
        )
    elif verdict == "suspicious":
        observations.append(
            Observation(
                source="llm-function",
                category="llm:function_suspicious",
                severity=ObservationSeverity.MEDIUM,
                message=f"LLM function analysis ({confidence:.0%}): {function.symbol} — {summary}",
                evidence={
                    "symbol": function.symbol,
                    "address": address,
                    "confidence": confidence,
                    "verdict": verdict,
                    "behaviors": behaviors,
                },
                addresses=[address],
                tags=["llm", "function"],
            )
        )
    elif verdict == "benign":
        # Anti-prompt-injection: if a high-triage function is called benign,
        # flag it for manual review rather than silently accepting the dismissal.
        if function.triage_score >= 0.85:
            observations.append(
                Observation(
                    source="llm-function",
                    category="llm:function_suspicious",
                    severity=ObservationSeverity.MEDIUM,
                    message=f"LLM dismissed high-triage function {function.symbol} as benign ({confidence:.0%}) — verify manually",
                    evidence={
                        "symbol": function.symbol,
                        "address": address,
                        "confidence": confidence,
                        "verdict": verdict,
                        "triage_score": function.triage_score,
                    },
                    addresses=[address],
                    tags=["llm", "function", "review_needed"],
                )
            )
        else:
            observations.append(
                Observation(
                    source="llm-function",
                    category="llm:function_benign",
                    severity=ObservationSeverity.INFO,
                    message=f"LLM: {function.symbol} appears benign — {summary}",
                    evidence={
                        "symbol": function.symbol,
                        "address": address,
                        "confidence": confidence,
                        "verdict": verdict,
                    },
                    addresses=[address],
                    tags=["llm", "function", "benign", "advisory"],
                )
            )

    # Individual findings from the LLM
    for finding in data.get("findings", []):
        sev_key = finding.get("severity", "medium")
        sev = SEVERITY_MAP.get(sev_key)
        if sev is None:
            continue
        observations.append(
            Observation(
                source="llm-function",
                category=f"llm:{finding.get('category', 'finding')}",
                severity=sev,
                message=finding.get("message", "LLM finding"),
                evidence={
                    "symbol": function.symbol,
                    "address": address,
                    "confidence": confidence,
                },
                addresses=[address],
                tags=["llm", "function"] + (["advisory"] if confidence < 0.7 else []),
            )
        )

    return observations


class LLMFunctionAnalysisPipeline:
    """Async pipeline stage: analyze decompiled functions with Claude."""

    def __init__(
        self,
        adapter: AnthropicLLMAdapter,
        budget: int = 50_000,
        min_triage_score: float = 0.5,
        max_functions: int = 5,
        max_code_length: int = 10_000,
    ) -> None:
        self._adapter = adapter
        self._budget = budget
        self._remaining = budget
        self._min_triage_score = min_triage_score
        self._max_functions = max_functions
        self._max_code_length = max_code_length

    async def analyze(self, artifact: ArtifactRecord) -> ArtifactRecord:
        """Analyze high-triage decompiled functions and add observations to the artifact."""
        functions = select_functions(
            artifact.functions,
            self._min_triage_score,
            self._max_functions,
            self._max_code_length,
        )

        if not functions:
            logger.info("LLM function analysis: no eligible functions")
            artifact.tool_runs.append(
                ToolExecution(
                    tool="llm-function",
                    status=ToolStatus.PASS,
                    summary="No decompiled functions eligible for LLM analysis",
                    details={"functions_analyzed": 0, "budget_remaining": self._remaining},
                )
            )
            return artifact

        logger.info(
            "LLM function analysis: %d functions selected (budget=%d)",
            len(functions),
            self._remaining,
        )

        total_in = 0
        total_out = 0
        analyzed = 0

        for func in functions:
            if self._remaining <= 0:
                logger.info("LLM function analysis: budget exhausted")
                break

            prompt = build_function_prompt(func, artifact)
            response_text, in_tok, out_tok = await self._adapter.analyze_file(
                prompt, remaining_budget=self._remaining
            )
            self._remaining -= in_tok + out_tok
            total_in += in_tok
            total_out += out_tok

            if not response_text:
                continue

            observations = parse_function_response(response_text, func)
            artifact.observations.extend(observations)
            analyzed += 1

        artifact.tool_runs.append(
            ToolExecution(
                tool="llm-function",
                status=ToolStatus.PASS,
                summary=f"LLM analyzed {analyzed} decompiled functions",
                details={
                    "functions_analyzed": analyzed,
                    "functions_selected": len(functions),
                    "tokens_in": total_in,
                    "tokens_out": total_out,
                    "budget_remaining": self._remaining,
                },
            )
        )

        return artifact
