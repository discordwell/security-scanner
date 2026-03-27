"""Repository-level scanner: walks a directory, classifies files, routes to analyzers."""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from .config import Settings, get_settings
from .models import (
    FileClassification,
    Observation,
    ObservationSeverity,
    RepoFileRecord,
    RepoReport,
    VerdictRecord,
    VerdictState,
)
from .service import AnalysisService
from .source_analysis import analyze_source

logger = logging.getLogger(__name__)

BINARY_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".elf", ".pyd", ".bin", ".com", ".scr", ".sys"}
SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".java", ".cs", ".rb", ".php", ".pl", ".lua", ".swift", ".kt", ".scala", ".r",
}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".cfg", ".env", ".conf"}
SCRIPT_EXTENSIONS = {".sh", ".bash", ".bat", ".cmd", ".ps1", ".psm1", ".vbs"}

SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build", ".eggs", ".mypy_cache", ".ruff_cache"}


def classify_file(path: Path, data: bytes | None = None) -> FileClassification:
    ext = path.suffix.lower()
    if ext in BINARY_EXTENSIONS:
        return FileClassification.BINARY
    if ext in SOURCE_EXTENSIONS:
        return FileClassification.SOURCE
    if ext in CONFIG_EXTENSIONS:
        return FileClassification.CONFIG
    if ext in SCRIPT_EXTENSIONS:
        return FileClassification.SCRIPT
    # Check magic bytes for extensionless files
    if data:
        if data.startswith(b"MZ") or data.startswith(b"\x7fELF"):
            return FileClassification.BINARY
        if data.startswith(b"#!"):
            return FileClassification.SCRIPT
    return FileClassification.UNKNOWN


def walk_repo(
    repo_path: Path,
    max_files: int = 5000,
    max_file_size: int = 10 * 1024 * 1024,
    skip_dirs: set[str] | None = None,
) -> list[tuple[Path, FileClassification]]:
    skip = skip_dirs or SKIP_DIRS
    results: list[tuple[Path, FileClassification]] = []
    seen_real: set[str] = set()

    for item in sorted(repo_path.rglob("*")):
        if len(results) >= max_files:
            logger.warning("Hit max file limit (%d), stopping walk", max_files)
            break

        # Skip excluded directories
        if any(part in skip for part in item.parts):
            continue

        if not item.is_file():
            continue

        # Avoid symlink loops
        try:
            real = str(item.resolve())
            if real in seen_real:
                continue
            seen_real.add(real)
        except OSError:
            continue

        # Skip oversized files
        try:
            size = item.stat().st_size
            if size > max_file_size or size == 0:
                continue
        except OSError:
            continue

        classification = classify_file(item)
        results.append((item, classification))

    return results


class RepoScanner:
    def __init__(
        self,
        analysis_service: AnalysisService | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.service = analysis_service or AnalysisService()
        self.settings = settings or get_settings()

    async def scan(
        self,
        repo_path: Path,
    ) -> RepoReport:
        repo_path = repo_path.resolve()
        logger.info("Scanning repo: %s", repo_path)

        classified = walk_repo(
            repo_path,
            max_files=self.settings.repo_max_files,
            max_file_size=self.settings.repo_max_file_size,
        )

        files: list[RepoFileRecord] = []
        binary_verdicts: list[VerdictRecord] = []
        all_observations: list[Observation] = []

        binary_count = 0
        source_count = 0

        for file_path, classification in classified:
            rel_path = str(file_path.relative_to(repo_path))

            try:
                data = file_path.read_bytes()
            except OSError:
                continue

            sha256 = hashlib.sha256(data).hexdigest()

            if classification == FileClassification.BINARY:
                binary_count += 1
                logger.info("Analyzing binary: %s", rel_path)
                try:
                    result = await self.service.submit(
                        filename=file_path.name,
                        data=data,
                        claimed_product=rel_path,
                    )
                    binary_verdicts.append(result.verdict)
                    all_observations.extend(result.verdict.observations)
                    files.append(RepoFileRecord(
                        path=rel_path,
                        classification=classification,
                        size=len(data),
                        sha256=sha256,
                        observations=result.verdict.observations,
                        metadata={"verdict": result.verdict.state.value},
                    ))
                except Exception as exc:
                    logger.warning("Binary analysis failed for %s: %s", rel_path, exc)
                    files.append(RepoFileRecord(
                        path=rel_path, classification=classification,
                        size=len(data), sha256=sha256,
                        metadata={"error": str(exc)},
                    ))
            elif classification in (FileClassification.SOURCE, FileClassification.CONFIG, FileClassification.SCRIPT):
                source_count += 1
                try:
                    content = data.decode("utf-8", errors="replace")
                except Exception:
                    continue
                obs = analyze_source(content, rel_path, classification)
                all_observations.extend(obs)
                files.append(RepoFileRecord(
                    path=rel_path,
                    classification=classification,
                    size=len(data),
                    sha256=sha256,
                    observations=obs,
                ))
            else:
                files.append(RepoFileRecord(
                    path=rel_path,
                    classification=classification,
                    size=len(data),
                    sha256=sha256,
                ))

        # Cross-file correlation: preinstall hooks pointing to dropper scripts
        cross_file_obs = self._correlate_preinstall_hooks(files, repo_path)
        all_observations.extend(cross_file_obs)
        for obs_item in cross_file_obs:
            # Attach to the package.json file record
            for f in files:
                if f.path.endswith("package.json"):
                    f.observations.append(obs_item)
                    break

        # Aggregate verdict
        aggregate, risk_summary = self._aggregate_verdict(all_observations, binary_verdicts)

        # Top findings sorted by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        top_findings = sorted(
            all_observations,
            key=lambda o: severity_order.get(o.severity.value, 5),
        )[:20]

        report = RepoReport(
            repo_path=str(repo_path),
            file_count=len(classified),
            files=files,
            binary_verdicts=binary_verdicts,
            aggregate_verdict=aggregate,
            risk_summary=risk_summary,
            top_findings=top_findings,
            statistics={
                "total_files": len(classified),
                "binaries": binary_count,
                "source_files": source_count,
                "total_observations": len(all_observations),
                "high_findings": sum(1 for o in all_observations if o.severity.value in ("high", "critical")),
                "medium_findings": sum(1 for o in all_observations if o.severity.value == "medium"),
            },
        )

        logger.info(
            "Repo scan complete: %d files, verdict=%s, %d observations",
            len(classified), aggregate.value, len(all_observations),
        )
        return report

    def _correlate_preinstall_hooks(
        self, files: list[RepoFileRecord], repo_path: Path,
    ) -> list[Observation]:
        """Cross-file: if a preinstall hook points to a file with dangerous imports, escalate."""
        import json as json_mod
        obs: list[Observation] = []

        for f in files:
            if not f.path.endswith("package.json"):
                continue
            try:
                pkg_data = (repo_path / f.path).read_text()
                pkg = json_mod.loads(pkg_data)
            except Exception:
                continue

            scripts = pkg.get("scripts") or {}
            for hook in ("preinstall", "postinstall", "preuninstall"):
                cmd = scripts.get(hook, "")
                if not cmd:
                    continue
                # Extract the target script filename from "node setup_bun.js" etc.
                parts = cmd.split()
                target_file = parts[-1] if parts else ""
                if not target_file.endswith((".js", ".ts", ".sh", ".py")):
                    continue

                # Find the target file in our scanned files
                for other in files:
                    if other.path == target_file or other.path.endswith("/" + target_file):
                        dangerous_imports = [
                            o for o in other.observations
                            if "child_process" in str(o.evidence) or "execSync" in str(o.evidence)
                            or "subprocess" in str(o.evidence)
                            or o.category in ("import:suspicious",)
                        ]
                        # Check if the script downloads/executes external code
                        try:
                            script_content = (repo_path / other.path).read_text()
                        except Exception:
                            script_content = ""

                        downloads_code = any(kw in script_content for kw in [
                            "curl", "wget", "fetch(", "https.get", "http.get",
                            "execSync", "spawn(", "bun.sh/install", "downloadAndSetup",
                        ])

                        if dangerous_imports or downloads_code:
                            obs.append(Observation(
                                source="repo-correlation",
                                category="supply_chain:preinstall_dropper",
                                severity=ObservationSeverity.HIGH,
                                message=f"Preinstall hook '{hook}' in {f.path} executes {target_file} which downloads and runs external code -- supply chain attack pattern (Shai-Hulud/worm).",
                                evidence={
                                    "package_json": f.path,
                                    "hook": hook,
                                    "command": cmd,
                                    "target_file": other.path,
                                    "downloads_code": downloads_code,
                                },
                                tags=["supply_chain", "preinstall", "dropper", "worm"],
                            ))
                        break
        return obs

    def _aggregate_verdict(
        self,
        observations: list[Observation],
        binary_verdicts: list[VerdictRecord],
    ) -> tuple[VerdictState, str]:
        has_critical = any(o.severity in (ObservationSeverity.HIGH, ObservationSeverity.CRITICAL) for o in observations)
        has_medium = any(o.severity == ObservationSeverity.MEDIUM for o in observations)
        binary_malicious = any(v.state == VerdictState.MALICIOUS for v in binary_verdicts)
        binary_suspicious = any(v.state == VerdictState.SUSPICIOUS for v in binary_verdicts)

        if has_critical or binary_malicious:
            return VerdictState.MALICIOUS, "Repository contains high-confidence malicious indicators."
        if has_medium or binary_suspicious:
            return VerdictState.SUSPICIOUS, "Repository contains indicators requiring analyst review."
        if observations:
            return VerdictState.INCONCLUSIVE, "Repository scanned but no strong signals found."
        return VerdictState.CLEAN, "No suspicious indicators found."
