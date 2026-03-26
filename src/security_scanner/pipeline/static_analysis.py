from __future__ import annotations

import logging

from ..adapters import CapaAdapter, GhidraAdapter, ProvenanceAdapter, YaraAdapter
from ..config import Settings
from ..models import ArtifactRecord, ExecutionPolicy, ProvenanceBundle

logger = logging.getLogger(__name__)


class StaticAnalysisPipeline:
    def __init__(
        self,
        yara: YaraAdapter | None = None,
        capa: CapaAdapter | None = None,
        ghidra: GhidraAdapter | None = None,
        provenance: ProvenanceAdapter | None = None,
        settings: Settings | None = None,
    ) -> None:
        settings = settings or Settings()
        self.yara = yara or YaraAdapter(rules_dir=settings.yara_rules_dir)
        self.capa = capa or CapaAdapter(capa_cmd=settings.capa_cmd)
        self.ghidra = ghidra or GhidraAdapter(
            ghidra_cmd=settings.ghidra_cmd,
            project_dir=settings.ghidra_project_dir,
            timeout=settings.ghidra_timeout,
            max_functions=settings.ghidra_max_functions,
        )
        self.provenance = provenance or ProvenanceAdapter()

    def analyze(
        self,
        artifact: ArtifactRecord,
        data: bytes,
        policy: ExecutionPolicy,
        provenance_bundle: ProvenanceBundle,
    ) -> ArtifactRecord:
        logger.info("Static analysis: %s", artifact.sha256[:12])
        yara_result = self.yara.analyze(data)
        capa_result = self.capa.analyze(artifact.strings, data=data)
        ghidra_result = self.ghidra.analyze(data, deep_limit=policy.deep_decompile_limit)
        provenance_summary, provenance_tool = self.provenance.analyze(provenance_bundle)

        artifact.observations.extend(yara_result.observations)
        artifact.observations.extend(capa_result.observations)
        artifact.observations.extend(ghidra_result.observations)
        artifact.functions.extend(ghidra_result.functions)
        artifact.tool_runs.extend(
            tool for tool in [yara_result.tool_run, capa_result.tool_run, ghidra_result.tool_run, provenance_tool] if tool is not None
        )
        artifact.provenance = provenance_summary

        return artifact
