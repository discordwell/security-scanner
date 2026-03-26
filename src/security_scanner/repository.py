from __future__ import annotations

import json
from pathlib import Path
from threading import RLock

from .config import get_settings
from .models import ArtifactRecord, BaselineRecord, StateSnapshot, SubmissionRecord, VerdictRecord


class JsonRepository:
    def __init__(self, state_file: Path | None = None) -> None:
        self.settings = get_settings()
        self.state_file = state_file or self.settings.state_file
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._state = self._load()

    def _load(self) -> StateSnapshot:
        if not self.state_file.exists():
            return StateSnapshot()
        payload = json.loads(self.state_file.read_text())
        return StateSnapshot.model_validate(payload)

    def _flush(self) -> None:
        temp = self.state_file.with_suffix(".tmp")
        temp.write_text(self._state.model_dump_json(indent=2))
        temp.replace(self.state_file)

    def save_artifact(self, artifact: ArtifactRecord) -> ArtifactRecord:
        with self._lock:
            self._state.artifacts[artifact.sha256] = artifact
            self._flush()
        return artifact

    def get_artifact(self, sha256: str) -> ArtifactRecord | None:
        return self._state.artifacts.get(sha256)

    def save_submission(self, submission: SubmissionRecord) -> SubmissionRecord:
        with self._lock:
            self._state.submissions[submission.id] = submission
            self._flush()
        return submission

    def get_submission(self, submission_id: str) -> SubmissionRecord | None:
        return self._state.submissions.get(submission_id)

    def save_verdict(self, verdict: VerdictRecord) -> VerdictRecord:
        with self._lock:
            self._state.verdicts[verdict.sha256] = verdict
            self._flush()
        return verdict

    def get_verdict(self, sha256: str) -> VerdictRecord | None:
        return self._state.verdicts.get(sha256)

    def save_baseline(self, baseline: BaselineRecord) -> BaselineRecord:
        with self._lock:
            self._state.baselines[baseline.id] = baseline
            self._flush()
        return baseline

    def list_baselines(self) -> list[BaselineRecord]:
        return list(self._state.baselines.values())

    def get_baseline(self, baseline_id: str) -> BaselineRecord | None:
        return self._state.baselines.get(baseline_id)
