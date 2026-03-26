from __future__ import annotations

import logging

from ..adapters import CapaAdapter, GhidraAdapter, ProvenanceAdapter, YaraAdapter
from ..models import ArtifactRecord, ExecutionPolicy, Observation, ObservationSeverity, ProvenanceBundle

logger = logging.getLogger(__name__)


class StaticAnalysisPipeline:
    def __init__(
        self,
        yara: YaraAdapter | None = None,
        capa: CapaAdapter | None = None,
        ghidra: GhidraAdapter | None = None,
        provenance: ProvenanceAdapter | None = None,
    ) -> None:
        self.yara = yara or YaraAdapter()
        self.capa = capa or CapaAdapter()
        self.ghidra = ghidra or GhidraAdapter()
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
        capa_result = self.capa.analyze(artifact.strings)
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
