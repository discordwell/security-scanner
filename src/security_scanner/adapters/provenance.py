from __future__ import annotations

from ..models import ProvenanceBundle, ProvenanceSummary, ToolExecution, ToolStatus


class ProvenanceAdapter:
    def analyze(self, bundle: ProvenanceBundle) -> tuple[ProvenanceSummary, ToolExecution]:
        trusted = bool(bundle.authenticode_trusted or bundle.sigstore_subject or bundle.in_toto_layout)
        summary = ProvenanceSummary(
            signer=bundle.claimed_signer,
            authenticode_status="trusted" if bundle.authenticode_trusted else "unknown",
            sigstore_status="present" if bundle.sigstore_subject else "unknown",
            in_toto_status="present" if bundle.in_toto_layout else "unknown",
            trusted=trusted,
            details=bundle.model_dump(exclude_none=True),
        )
        execution = ToolExecution(
            tool="provenance",
            status=ToolStatus.PASS if trusted else ToolStatus.UNAVAILABLE,
            summary="Validated provided provenance metadata." if trusted else "No machine-verifiable provenance was provided.",
            details=summary.details,
        )
        return summary, execution
