from __future__ import annotations

import json
import logging
import re

from ..adapters.types import AdapterResult
from ..models import (
    ArtifactRecord,
    Observation,
    ObservationSeverity,
    ToolExecution,
    ToolStatus,
    VerdictRecord,
    VerdictState,
)
from ..verdict_rules import attack_vector_categories, is_compound_attack_chain

logger = logging.getLogger(__name__)

_JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n\s*```", re.DOTALL)

_VERDICT_MAP = {
    "clean": VerdictState.CLEAN,
    "suspicious": VerdictState.SUSPICIOUS,
    "malicious": VerdictState.MALICIOUS,
    "inconclusive": VerdictState.INCONCLUSIVE,
}

FUSION_SYSTEM_PROMPT = """\
You are a senior malware analyst making a final verdict on a binary submission.
You have access to results from multiple analysis tools. Your job is to synthesize
all signals into a single verdict with clear reasoning.

Guidelines:
- Consider the FULL context: a VirtualAlloc call in a signed Microsoft binary is normal;
  the same call in an unsigned binary with C2 strings is suspicious.
- Provenance (code signing, Sigstore) is a strong trust signal but not absolute —
  signed malware exists.
- Baseline matches mean this binary closely resembles a known-good version.
- Multiple MEDIUM findings from different tools that form a coherent attack pattern
  (recon → injection → C2 → exfiltration) should escalate to MALICIOUS.
- A single HIGH finding from a heuristic (not a real tool) with trusted provenance
  may warrant downgrade to SUSPICIOUS.
- Coverage gaps mean the analysis is incomplete — factor this into confidence.

Respond with a JSON block:

```json
{
  "verdict": "clean" | "suspicious" | "malicious" | "inconclusive",
  "confidence": 0.0-1.0,
  "summary": "2-3 sentence reasoning explaining your verdict",
  "key_factors": ["factor1", "factor2", "factor3"],
  "dissent": "If you disagree with the rule-based verdict, explain why. Otherwise null."
}
```"""


def build_fusion_prompt(
    rule_verdict: VerdictRecord,
    root_artifact: ArtifactRecord,
    artifacts: list[ArtifactRecord],
) -> str:
    """Build a prompt summarizing all analysis signals for LLM verdict reasoning."""
    all_observations = rule_verdict.observations

    # Group observations by source
    by_source: dict[str, list[Observation]] = {}
    for obs in all_observations:
        by_source.setdefault(obs.source, []).append(obs)

    obs_summary = []
    for source, obs_list in sorted(by_source.items()):
        obs_summary.append(f"\n### {source} ({len(obs_list)} findings)")
        for obs in obs_list[:10]:
            obs_summary.append(f"  - [{obs.severity.value}] {obs.message}")
        if len(obs_list) > 10:
            obs_summary.append(f"  - ... and {len(obs_list) - 10} more")
    obs_text = "\n".join(obs_summary) or "  (no observations)"

    # Provenance
    prov = root_artifact.provenance
    prov_text = (
        f"- Trusted: {prov.trusted}\n"
        f"- Authenticode: {prov.authenticode_status}\n"
        f"- Sigstore: {prov.sigstore_status}\n"
        f"- in-toto: {prov.in_toto_status}"
    )
    if prov.signer:
        prov_text += f"\n- Signer: {prov.signer}"

    # Baseline
    bl = root_artifact.baseline_diff
    baseline_text = (
        f"- Matched: {bl.matched}\n"
        f"- Distance: {bl.distance:.2f}\n"
        f"- Shared functions: {bl.shared_functions}/{bl.total_functions}"
    )
    if bl.new_regions:
        baseline_text += f"\n- New regions: {', '.join(bl.new_regions[:5])}"
    if bl.missing_regions:
        baseline_text += f"\n- Missing regions: {', '.join(bl.missing_regions[:5])}"

    # Behavior
    behavior_text = ""
    if rule_verdict.behavior:
        behavior_text = "\n## Behavioral Events\n"
        for event in rule_verdict.behavior[:10]:
            behavior_text += f"  - [{event.source}] {event.summary}\n"

    # Functions
    func_text = ""
    if rule_verdict.functions:
        func_text = "\n## Decompiled Functions\n"
        for func in sorted(rule_verdict.functions, key=lambda f: f.triage_score, reverse=True)[:5]:
            func_text += f"  - {func.symbol} (score={func.triage_score:.2f}): {func.reason}\n"

    return f"""{FUSION_SYSTEM_PROMPT}

## Submission

- **SHA256**: {root_artifact.sha256}
- **Filename**: {root_artifact.filename}
- **Format**: {root_artifact.format.value}
- **Size**: {root_artifact.size:,} bytes
- **Artifacts analyzed**: {len(artifacts)}

## Rule-Based Verdict

- **State**: {rule_verdict.state.value}
- **Reasons**: {'; '.join(rule_verdict.reasons)}
- **Pending actions**: {'; '.join(rule_verdict.pending_actions) or 'none'}

## Provenance

{prov_text}

## Baseline Comparison

{baseline_text}

## Observations (by source)
{obs_text}
{behavior_text}{func_text}
Synthesize all signals above into a final verdict."""


def parse_fusion_response(
    response_text: str,
    rule_verdict: VerdictRecord,
) -> VerdictRecord:
    """Parse LLM fusion response and merge with rule-based verdict."""
    match = _JSON_BLOCK_RE.search(response_text)
    if not match:
        logger.warning("No JSON block in LLM fusion response; keeping rule-based verdict")
        return rule_verdict

    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse LLM fusion JSON: %s", exc)
        return rule_verdict

    llm_verdict_str = data.get("verdict", "").lower()
    llm_state = _VERDICT_MAP.get(llm_verdict_str)
    if llm_state is None:
        logger.warning("Unknown LLM verdict '%s'; keeping rule-based", llm_verdict_str)
        return rule_verdict

    try:
        confidence = float(data.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5

    summary = data.get("summary", "")
    key_factors = data.get("key_factors", [])
    dissent = data.get("dissent")

    # Build the merged verdict
    final_state = llm_state
    reasons = list(rule_verdict.reasons)

    if llm_state != rule_verdict.state:
        reasons.append(
            f"LLM override ({confidence:.0%} confidence): {rule_verdict.state.value} → {llm_state.value}. {dissent or summary}"
        )
    else:
        reasons.append(f"LLM confirmed ({confidence:.0%} confidence): {summary}")

    # Add an observation recording the LLM fusion decision
    fusion_obs = Observation(
        source="llm-fusion",
        category="llm:verdict",
        severity=ObservationSeverity.INFO,
        message=f"LLM fusion verdict: {llm_state.value} ({confidence:.0%}) — {summary}",
        evidence={
            "llm_verdict": llm_state.value,
            "rule_verdict": rule_verdict.state.value,
            "confidence": confidence,
            "key_factors": key_factors,
            "dissent": dissent,
            "overridden": llm_state != rule_verdict.state,
        },
        tags=["llm", "fusion", "verdict"],
    )

    return VerdictRecord(
        sha256=rule_verdict.sha256,
        state=final_state,
        summary=summary or rule_verdict.summary,
        reasons=reasons,
        observations=[*rule_verdict.observations, fusion_obs],
        functions=rule_verdict.functions,
        behavior=rule_verdict.behavior,
        pending_actions=rule_verdict.pending_actions,
    )


class FusionPipeline:
    def __init__(self, adapter=None, llm_budget: int = 30_000) -> None:
        self._adapter = adapter
        self._llm_budget = llm_budget

    @property
    def has_llm(self) -> bool:
        return self._adapter is not None

    def verdict_for(self, root_artifact: ArtifactRecord, artifacts: list[ArtifactRecord]) -> VerdictRecord:
        all_observations = [observation for artifact in artifacts for observation in artifact.observations]
        all_functions = [function for artifact in artifacts for function in artifact.functions]
        all_behavior = [event for artifact in artifacts for event in artifact.behavior]
        all_tool_runs = [tool for artifact in artifacts for tool in artifact.tool_runs]

        critical_or_high = [obs for obs in all_observations if obs.severity in {ObservationSeverity.HIGH, ObservationSeverity.CRITICAL}]
        medium = [obs for obs in all_observations if obs.severity == ObservationSeverity.MEDIUM]
        reasons: list[str] = []
        pending_actions: list[str] = []
        state = VerdictState.INCONCLUSIVE

        # Distinct attack-vector categories among MEDIUM findings (shared rule, see
        # verdict_rules) -- used both to gate escalation and to explain it.
        distinct_attack_vectors = attack_vector_categories(medium)

        if critical_or_high:
            state = VerdictState.MALICIOUS
            reasons.append("High-confidence static evidence indicates malicious behavior or tooling.")
        elif is_compound_attack_chain(medium):
            # Evasion-tuned malware deliberately avoids any single HIGH signal.
            # 3+ MEDIUMs spanning 3+ distinct attack vectors is a coherent attack chain.
            state = VerdictState.MALICIOUS
            reasons.append(
                f"Multiple MEDIUM findings ({len(medium)}) across {len(distinct_attack_vectors)} "
                f"distinct attack-vector categories ({', '.join(sorted(distinct_attack_vectors))}) "
                f"indicate a coordinated attack chain."
            )
        elif medium or root_artifact.baseline_diff.distance >= 0.2:
            state = VerdictState.SUSPICIOUS
            reasons.append("Static heuristics or baseline divergence require analyst review.")

        provenance_trusted = root_artifact.provenance.trusted
        unresolved_coverage = any(obs.category == "coverage_gap" for obs in all_observations)
        dynamic_gap = any(
            tool.tool in {"cape", "drakvuf"} and tool.status.value == "unavailable" and tool.details.get("enabled")
            for tool in all_tool_runs
        )

        if not critical_or_high and not medium and provenance_trusted and root_artifact.baseline_diff.matched and not unresolved_coverage:
            state = VerdictState.CLEAN
            reasons = ["Trusted provenance and baseline match with no unresolved suspicious evidence."]

        if state == VerdictState.SUSPICIOUS and provenance_trusted and root_artifact.baseline_diff.matched and not unresolved_coverage:
            state = VerdictState.CLEAN
            reasons = ["Trusted provenance and baseline match with no unresolved suspicious evidence."]

        if not root_artifact.provenance.trusted and root_artifact.baseline_diff.baseline_id is None and not critical_or_high and not medium:
            state = VerdictState.INCONCLUSIVE
            reasons = ["No trusted provenance or baseline was available to support a clean verdict."]

        if unresolved_coverage:
            pending_actions.append("Run deeper decompilation on promoted functions or configure an external disassembler.")
        if dynamic_gap and state != VerdictState.MALICIOUS:
            pending_actions.append("Configure CAPE/DRAKVUF for native detonation before issuing a final clean decision.")
        if root_artifact.baseline_diff.baseline_id is None:
            pending_actions.append("Register a trusted baseline for this product or signer.")

        summary = {
            VerdictState.CLEAN: "Artifact met the current clean policy gates.",
            VerdictState.SUSPICIOUS: "Artifact requires analyst review before release.",
            VerdictState.MALICIOUS: "Artifact exhibits high-confidence malicious characteristics.",
            VerdictState.INCONCLUSIVE: "Artifact could not be cleared with current evidence coverage.",
        }[state]

        logger.info("Fusion verdict: %s for %s (%d observations, %d pending actions)",
                    state.value, root_artifact.sha256[:12], len(all_observations), len(pending_actions))

        return VerdictRecord(
            sha256=root_artifact.sha256,
            state=state,
            summary=summary,
            reasons=reasons,
            observations=all_observations,
            functions=all_functions,
            behavior=all_behavior,
            pending_actions=pending_actions,
        )

    async def verdict_for_with_llm(
        self,
        root_artifact: ArtifactRecord,
        artifacts: list[ArtifactRecord],
    ) -> VerdictRecord:
        """Compute rule-based verdict, then refine with LLM reasoning."""
        rule_verdict = self.verdict_for(root_artifact, artifacts)

        if self._adapter is None:
            return rule_verdict

        prompt = build_fusion_prompt(rule_verdict, root_artifact, artifacts)
        response_text, in_tok, out_tok = await self._adapter.analyze_file(
            prompt, remaining_budget=self._llm_budget,
        )

        if not response_text:
            logger.info("LLM fusion: no response, keeping rule-based verdict")
            return rule_verdict

        logger.info("LLM fusion: %d in / %d out tokens used", in_tok, out_tok)
        return parse_fusion_response(response_text, rule_verdict)
