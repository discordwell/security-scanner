from __future__ import annotations

from ..adapters import AngrAdapter
from ..models import ArtifactRecord, ExecutionPolicy


class SymbolicPipeline:
    def __init__(self, angr: AngrAdapter | None = None) -> None:
        self.angr = angr or AngrAdapter()

    def analyze(self, artifact: ArtifactRecord, policy: ExecutionPolicy) -> ArtifactRecord:
        result = self.angr.analyze(suspicious_functions=len(artifact.functions), enabled=policy.enable_symbolic_execution)
        artifact.observations.extend(result.observations)
        artifact.behavior.extend(result.behavior)
        if result.tool_run is not None:
            artifact.tool_runs.append(result.tool_run)
        return artifact
