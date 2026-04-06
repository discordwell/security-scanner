"""Auto-generate YARA rules from confirmed malicious samples.

When a binary receives a MALICIOUS verdict with high LLM confidence,
this pipeline generates YARA rules from its distinctive features and
saves them to the auto-rules directory for future scans.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..adapters.anthropic_llm import AnthropicLLMAdapter
from ..models import ArtifactRecord, Observation, ObservationSeverity, VerdictRecord, VerdictState

logger = logging.getLogger(__name__)

_YARA_BLOCK_RE = re.compile(r"```(?:yara)?\s*\n(rule\s+\w+.*?)```", re.DOTALL)

# Basic structural validation
_RULE_NAME_RE = re.compile(r"^rule\s+(\w+)", re.MULTILINE)

YARA_GEN_PROMPT = """\
You are a YARA rule author. Given the analysis results for a confirmed malicious binary,
generate one or more YARA rules that would detect this malware or its family.

Guidelines:
- Use unique, distinctive strings and byte patterns — avoid generic matches that would
  trigger on legitimate software.
- Prefer hex byte patterns over ASCII strings for resilience against trivial modification.
- Include metadata: author, description, date, severity, reference to SHA256.
- Use reasonable conditions: multiple string matches with AND/OR logic, filesize constraints,
  entry point checks where applicable.
- Name rules descriptively: e.g., `rule Mal_ProcessInjector_VirtualAlloc_C2`.
- Each rule should be self-contained and syntactically valid.
- Do NOT use `pe` module imports unless the binary is PE format.
- Keep rules focused — one rule per technique or behavior cluster.

Wrap each rule in a ```yara block:

```yara
rule Example_Malware {
    meta:
        author = "auto-generated"
        description = "Detects example malware family"
        date = "2026-04-05"
        severity = "high"

    strings:
        $s1 = { 4D 5A 90 00 }
        $s2 = "suspicious_string"

    condition:
        $s1 at 0 and $s2
}
```"""


def build_yara_gen_prompt(
    artifact: ArtifactRecord,
    verdict: VerdictRecord,
) -> str:
    """Build a prompt for generating YARA rules from a malicious sample."""
    # Collect distinctive strings
    strings_text = "\n".join(f"  - {s}" for s in artifact.strings[:50]) or "  (none)"

    # Collect observations by source
    obs_text = []
    for obs in verdict.observations[:20]:
        if obs.severity in {ObservationSeverity.MEDIUM, ObservationSeverity.HIGH, ObservationSeverity.CRITICAL}:
            obs_text.append(f"  - [{obs.severity.value}] {obs.source}: {obs.message}")
    obs_summary = "\n".join(obs_text) or "  (no significant findings)"

    # LLM fusion summary if available
    fusion_obs = [o for o in verdict.observations if o.source == "llm-fusion"]
    fusion_text = ""
    if fusion_obs:
        fusion_text = f"\n### LLM Analysis Summary\n{fusion_obs[0].message}\n"

    # Decompiled functions (if available)
    func_text = ""
    decompiled = [f for f in verdict.functions if f.decompiled_code]
    if decompiled:
        func_text = "\n### Decompiled Functions (suspicious)\n"
        for f in sorted(decompiled, key=lambda x: x.triage_score, reverse=True)[:3]:
            code_preview = f.decompiled_code[:500] if f.decompiled_code else ""
            func_text += f"\n**{f.symbol}** (score={f.triage_score:.2f}):\n```c\n{code_preview}\n```\n"

    return f"""{YARA_GEN_PROMPT}

## Malicious Sample Details

- **SHA256**: {artifact.sha256}
- **Filename**: {artifact.filename}
- **Format**: {artifact.format.value}
- **Size**: {artifact.size:,} bytes
- **Verdict**: {verdict.state.value} ({'; '.join(verdict.reasons[:3])})

### Extracted Strings
{strings_text}

### Key Observations
{obs_summary}
{fusion_text}{func_text}
Generate YARA rules to detect this malware. Focus on the most distinctive indicators."""


def parse_yara_rules(response_text: str) -> list[tuple[str, str]]:
    """Extract and validate YARA rules from LLM response.

    Returns list of (rule_name, rule_text) tuples.
    """
    rules = []
    for match in _YARA_BLOCK_RE.finditer(response_text):
        rule_text = match.group(1).strip()
        name_match = _RULE_NAME_RE.search(rule_text)
        if not name_match:
            logger.warning("YARA block missing rule name, skipping")
            continue

        rule_name = name_match.group(1)

        # Basic structural validation
        if "strings:" not in rule_text and "condition:" not in rule_text:
            logger.warning("YARA rule '%s' missing strings/condition section, skipping", rule_name)
            continue

        if "condition:" not in rule_text:
            logger.warning("YARA rule '%s' missing condition section, skipping", rule_name)
            continue

        rules.append((rule_name, rule_text))

    return rules


class YaraGenerationPipeline:
    """Post-verdict pipeline: generate YARA rules from confirmed malicious samples."""

    def __init__(
        self,
        adapter: AnthropicLLMAdapter,
        rules_dir: Path,
        budget: int = 20_000,
        min_confidence: float = 0.8,
    ) -> None:
        self._adapter = adapter
        self._rules_dir = rules_dir
        self._budget = budget
        self._min_confidence = min_confidence

    async def generate(
        self,
        artifact: ArtifactRecord,
        verdict: VerdictRecord,
    ) -> list[str]:
        """Generate YARA rules for a malicious sample.

        Returns list of generated rule names.
        """
        if verdict.state != VerdictState.MALICIOUS:
            return []

        # Check LLM fusion confidence if available
        fusion_obs = [o for o in verdict.observations if o.source == "llm-fusion"]
        if fusion_obs:
            confidence = fusion_obs[0].evidence.get("confidence", 0.0)
            if confidence < self._min_confidence:
                logger.info(
                    "Skipping YARA generation: LLM confidence %.2f < threshold %.2f",
                    confidence, self._min_confidence,
                )
                return []

        prompt = build_yara_gen_prompt(artifact, verdict)
        response_text, in_tok, out_tok = await self._adapter.analyze_file(
            prompt, remaining_budget=self._budget,
        )

        if not response_text:
            logger.info("YARA generation: no LLM response")
            return []

        rules = parse_yara_rules(response_text)
        if not rules:
            logger.info("YARA generation: no valid rules extracted from response")
            return []

        # Write rules to auto directory
        self._rules_dir.mkdir(parents=True, exist_ok=True)
        rule_file = self._rules_dir / f"{artifact.sha256[:12]}.yar"
        rule_text = "\n\n".join(text for _, text in rules)
        rule_file.write_text(rule_text)

        rule_names = [name for name, _ in rules]
        logger.info(
            "YARA generation: wrote %d rules to %s (%d in / %d out tokens)",
            len(rules), rule_file, in_tok, out_tok,
        )
        return rule_names
