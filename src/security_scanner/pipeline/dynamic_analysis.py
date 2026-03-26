from __future__ import annotations

import logging

from ..adapters import CapeAdapter, DrakvufAdapter
from ..config import Settings
from ..models import ArtifactRecord, ExecutionPolicy

logger = logging.getLogger(__name__)


class DynamicAnalysisPipeline:
    def __init__(
        self,
        cape: CapeAdapter | None = None,
        drakvuf: DrakvufAdapter | None = None,
        settings: Settings | None = None,
    ) -> None:
        settings = settings or Settings()
        self.cape = cape or CapeAdapter(cape_url=settings.cape_cmd)
        self.drakvuf = drakvuf or DrakvufAdapter(drakvuf_url=settings.drakvuf_cmd)

    def analyze(self, artifact: ArtifactRecord, policy: ExecutionPolicy, data: bytes | None = None) -> ArtifactRecord:
        logger.info("Dynamic analysis: %s (enabled=%s)", artifact.sha256[:12], policy.enable_dynamic_analysis)
        cape_result = self.cape.analyze(enabled=policy.enable_dynamic_analysis, data=data)
        drakvuf_result = self.drakvuf.analyze(enabled=policy.enable_dynamic_analysis, data=data)
        artifact.behavior.extend(cape_result.behavior)
        artifact.behavior.extend(drakvuf_result.behavior)
        artifact.observations.extend(cape_result.observations)
        artifact.observations.extend(drakvuf_result.observations)
        artifact.tool_runs.extend(tool for tool in [cape_result.tool_run, drakvuf_result.tool_run] if tool is not None)
        return artifact
