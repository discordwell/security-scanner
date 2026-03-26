from __future__ import annotations

import logging

from ..models import ArtifactRecord, ObservationSeverity, VerdictRecord, VerdictState

logger = logging.getLogger(__name__)


class FusionPipeline:
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

        if critical_or_high:
            state = VerdictState.MALICIOUS
            reasons.append("High-confidence static evidence indicates malicious behavior or tooling.")
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
