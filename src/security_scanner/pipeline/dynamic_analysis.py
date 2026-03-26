from __future__ import annotations

from ..adapters import CapeAdapter, DrakvufAdapter
from ..models import ArtifactRecord, ExecutionPolicy


class DynamicAnalysisPipeline:
    def __init__(self, cape: CapeAdapter | None = None, drakvuf: DrakvufAdapter | None = None) -> None:
        self.cape = cape or CapeAdapter()
        self.drakvuf = drakvuf or DrakvufAdapter()

    def analyze(self, artifact: ArtifactRecord, policy: ExecutionPolicy) -> ArtifactRecord:
        cape_result = self.cape.analyze(enabled=policy.enable_dynamic_analysis)
        drakvuf_result = self.drakvuf.analyze(enabled=policy.enable_dynamic_analysis)
        artifact.behavior.extend(cape_result.behavior)
        artifact.behavior.extend(drakvuf_result.behavior)
        artifact.tool_runs.extend(tool for tool in [cape_result.tool_run, drakvuf_result.tool_run] if tool is not None)
        return artifact
