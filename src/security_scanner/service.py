from __future__ import annotations

import logging
from dataclasses import dataclass

from .baselines import build_baseline_record, compare_against_baselines
from .models import ArtifactRecord, ExecutionPolicy, ProvenanceBundle, SubmissionRecord, SubmissionStatus, VerdictRecord
from .pipeline.dynamic_analysis import DynamicAnalysisPipeline
from .pipeline.fusion import FusionPipeline
from .pipeline.ingest import IngestPipeline
from .pipeline.static_analysis import StaticAnalysisPipeline
from .pipeline.symbolic import SymbolicPipeline
from .repository import JsonRepository
from .storage import LocalArtifactStore

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SubmissionResult:
    submission: SubmissionRecord
    artifacts: list[ArtifactRecord]
    verdict: VerdictRecord


class AnalysisService:
    def __init__(
        self,
        repository: JsonRepository | None = None,
        artifact_store: LocalArtifactStore | None = None,
        ingest: IngestPipeline | None = None,
        static: StaticAnalysisPipeline | None = None,
        dynamic: DynamicAnalysisPipeline | None = None,
        symbolic: SymbolicPipeline | None = None,
        fusion: FusionPipeline | None = None,
    ) -> None:
        self.repository = repository or JsonRepository()
        self.artifact_store = artifact_store or LocalArtifactStore()
        self.ingest = ingest or IngestPipeline(self.artifact_store)
        self.static = static or StaticAnalysisPipeline()
        self.dynamic = dynamic or DynamicAnalysisPipeline()
        self.symbolic = symbolic or SymbolicPipeline()
        self.fusion = fusion or FusionPipeline()

    def submit(
        self,
        filename: str,
        data: bytes,
        policy: ExecutionPolicy | None = None,
        claimed_product: str | None = None,
        provenance_bundle: ProvenanceBundle | dict | None = None,
    ) -> SubmissionResult:
        logger.info("Submission received: %s", filename)
        policy = policy or ExecutionPolicy()
        if provenance_bundle is None:
            provenance_bundle = ProvenanceBundle()
        elif isinstance(provenance_bundle, dict):
            provenance_bundle = ProvenanceBundle.model_validate(provenance_bundle)

        ingest_result = self.ingest.ingest(
            filename=filename,
            data=data,
            max_depth=policy.recursive_unpack_depth,
            max_strings=policy.max_strings,
        )
        all_artifacts = [ingest_result.root, *ingest_result.extracted]

        submission = SubmissionRecord(
            filename=filename,
            root_sha256=ingest_result.root.sha256,
            artifact_shas=[artifact.sha256 for artifact in all_artifacts],
            policy=policy,
            claimed_product=claimed_product,
            claimed_signer=provenance_bundle.claimed_signer,
            status=SubmissionStatus.ANALYZING,
        )

        analyzed_artifacts: list[ArtifactRecord] = []
        for artifact in all_artifacts:
            artifact_data = self.artifact_store.get(artifact.sha256)
            artifact = self.static.analyze(artifact, artifact_data, policy, provenance_bundle)
            artifact.baseline_diff = compare_against_baselines(
                artifact=artifact,
                baselines=self.repository.list_baselines(),
                claimed_product=claimed_product,
                claimed_signer=provenance_bundle.claimed_signer,
            )
            artifact = self.dynamic.analyze(artifact, policy)
            artifact = self.symbolic.analyze(artifact, policy)
            self.repository.save_artifact(artifact)
            analyzed_artifacts.append(artifact)

        root_artifact = next(artifact for artifact in analyzed_artifacts if artifact.sha256 == submission.root_sha256)
        verdict = self.fusion.verdict_for(root_artifact, analyzed_artifacts)
        logger.info("Verdict for %s: %s", filename, verdict.state.value)
        self.repository.save_verdict(verdict)

        submission.status = SubmissionStatus.COMPLETE
        submission.verdict_state = verdict.state
        submission.verdict_summary = verdict.summary
        submission.pending_actions = verdict.pending_actions
        self.repository.save_submission(submission)

        return SubmissionResult(submission=submission, artifacts=analyzed_artifacts, verdict=verdict)

    def register_baseline(
        self,
        filename: str,
        data: bytes,
        product: str,
        version: str | None,
        signer: str | None,
    ):
        logger.info("Registering baseline: %s product=%s", filename, product)
        ingest_result = self.ingest.ingest(filename=filename, data=data, max_depth=0, max_strings=256)
        artifact = self.static.analyze(
            ingest_result.root,
            data,
            policy=ExecutionPolicy(),
            provenance_bundle=ProvenanceBundle(claimed_signer=signer, authenticode_trusted=bool(signer)),
        )
        self.repository.save_artifact(artifact)
        baseline = build_baseline_record(
            artifact=artifact,
            product=product,
            version=version,
            signer=signer,
            metadata={"filename": filename},
        )
        self.repository.save_baseline(baseline)
        return baseline

    def get_submission(self, submission_id: str) -> SubmissionRecord | None:
        return self.repository.get_submission(submission_id)

    def get_artifact(self, sha256: str) -> ArtifactRecord | None:
        return self.repository.get_artifact(sha256)

    def get_verdict(self, sha256: str) -> VerdictRecord | None:
        return self.repository.get_verdict(sha256)
