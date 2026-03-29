"""Cross-file reference mapping for detecting split-payload attacks."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import FileClassification, Observation, ObservationSeverity, RepoFileRecord

logger = logging.getLogger(__name__)

# --- Reference parsing patterns ---

# Python
_PY_IMPORT_RE = re.compile(r'^\s*(?:from\s+([\w.]+)\s+)?import\s+([\w.]+)', re.MULTILINE)
_PY_OPEN_RE = re.compile(r'''open\s*\(\s*['"]([\w./\\-]+)['"]''')
_PY_LOAD_FILE_RE = re.compile(r'''(?:json|yaml|toml)\.load\s*\(.*?open\s*\(\s*['"]([\w./\\-]+)['"]''')
_PY_EXEC_OPEN_RE = re.compile(r'''exec\s*\(.*?open\s*\(\s*['"]([\w./\\-]+)['"]''')

# JavaScript / TypeScript
_JS_REQUIRE_RE = re.compile(r'''require\s*\(\s*['"](\.\.?/[\w./\\-]+)['"]''')
_JS_IMPORT_RE = re.compile(r'''import\s+.*?\s+from\s+['"](\.\.?/[\w./\\-]+)['"]''')
_JS_READFILE_RE = re.compile(r'''(?:readFileSync|readFile)\s*\(\s*['"]([\w./\\-]+)['"]''')

# Well-known entry points, manifests, build files
ENTRY_POINT_NAMES = {
    "setup.py", "main.py", "app.py", "server.py", "index.js", "index.ts",
    "main.go", "main.rs", "Program.cs", "__main__.py",
}
MANIFEST_NAMES = {
    "package.json", "requirements.txt", "pyproject.toml", "Pipfile",
    "go.mod", "Cargo.toml", "Gemfile", "composer.json",
}
BUILD_FILE_NAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", "Justfile", "Taskfile.yml", "Jenkinsfile",
}
BUILD_FILE_PATTERNS = {".github/workflows/", ".gitlab-ci.yml", ".circleci/"}

# Observation categories that indicate data vs exec capability
DATA_CATEGORIES = {
    "obfuscation:base64", "obfuscation:hex_escape", "payload:long_string",
    "payload:encoded", "payload:shellcode", "payload:data_uri",
    "obfuscation:invisible_unicode",
}
# Strong data indicators: a single one of these is enough to classify as DATA_CAPABLE
STRONG_DATA_CATEGORIES = {"payload:shellcode", "obfuscation:invisible_unicode", "payload:encoded"}

EXEC_CATEGORIES = {
    "obfuscation:eval_exec", "obfuscation:import_exec_chain",
    "obfuscation:dynamic_import", "obfuscation:marshal",
    "obfuscation:nested_decode",
    # Note: "import:suspicious" intentionally excluded -- merely importing
    # socket/subprocess doesn't make a file exec-capable. Real split-payload
    # attacks always have actual eval/exec/compile in the loader.
}


@dataclass(slots=True)
class FileReference:
    source_path: str
    target_path: str
    ref_type: str  # "import", "require", "open", "exec_open"
    line_number: int | None = None
    context: str = ""


@dataclass(slots=True)
class CrossFileLead:
    data_file: str
    exec_file: str
    connection: str
    data_indicators: list[str]
    exec_indicators: list[str]
    severity: ObservationSeverity
    explanation: str


@dataclass(slots=True)
class ReferenceGraph:
    references: list[FileReference] = field(default_factory=list)
    leads: list[CrossFileLead] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    build_files: list[str] = field(default_factory=list)


def build_reference_graph(
    files: list[RepoFileRecord],
    repo_path: Path,
) -> ReferenceGraph:
    graph = ReferenceGraph()
    file_paths = {f.path for f in files}
    file_by_path: dict[str, RepoFileRecord] = {f.path: f for f in files}

    # Identify well-known file types
    for f in files:
        name = Path(f.path).name
        if name in ENTRY_POINT_NAMES or f.path.endswith("__init__.py"):
            graph.entry_points.append(f.path)
        if name in MANIFEST_NAMES:
            graph.manifests.append(f.path)
        if name in BUILD_FILE_NAMES or any(p in f.path for p in BUILD_FILE_PATTERNS):
            graph.build_files.append(f.path)

    # Pass 1: Parse references
    for f in files:
        if f.classification in (FileClassification.BINARY, FileClassification.UNKNOWN):
            continue
        try:
            content = (repo_path / f.path).read_text(errors="replace")
        except OSError:
            continue

        refs = _parse_references(f.path, content, f.classification)
        for ref in refs:
            resolved = _resolve_path(ref.target_path, f.path, file_paths, repo_path)
            if resolved:
                ref.target_path = resolved
                graph.references.append(ref)

    # Pass 2: Classify files by capability
    data_files: set[str] = set()
    exec_files: set[str] = set()
    for f in files:
        cats = {o.category for o in f.observations}
        data_hits = cats & DATA_CATEGORIES
        # Require 2+ data indicators OR a single strong one (shellcode, invisible unicode)
        # This prevents crypto constants (single hex_escape) from flooding the graph
        if len(data_hits) >= 2 or (data_hits & STRONG_DATA_CATEGORIES):
            data_files.add(f.path)
        if cats & EXEC_CATEGORIES:
            exec_files.add(f.path)

    # Pass 3: Detect cross-file leads (depth 2)
    # "Who imports data_path?" → reverse adjacency (if loader.py imports data.py, reverse gives data.py → loader.py)
    reverse_adj = _build_adjacency(graph.references, reverse=True)
    # "What does exec_path import?" → forward adjacency
    forward_adj = _build_adjacency(graph.references, reverse=False)

    # Direction 1: From data file, find exec files that import it (via reverse adj)
    for data_path in data_files:
        reachable = _reachable_from(data_path, reverse_adj, max_depth=2)
        for exec_path in exec_files:
            if exec_path == data_path:
                continue
            if exec_path in reachable:
                depth = reachable[exec_path]
                data_rec = file_by_path.get(data_path)
                exec_rec = file_by_path.get(exec_path)
                if not data_rec or not exec_rec:
                    continue
                data_indicators = [o.category for o in data_rec.observations if o.category in DATA_CATEGORIES]
                exec_indicators = [o.category for o in exec_rec.observations if o.category in EXEC_CATEGORIES]
                graph.leads.append(CrossFileLead(
                    data_file=data_path,
                    exec_file=exec_path,
                    connection="direct" if depth == 1 else f"transitive (depth {depth})",
                    data_indicators=data_indicators,
                    exec_indicators=exec_indicators,
                    severity=ObservationSeverity.HIGH if depth == 1 else ObservationSeverity.MEDIUM,
                    explanation=f"Encoded data in {data_path} is reachable from exec-capable {exec_path} (depth {depth}).",
                ))

    # Direction 2: From exec file, find data files it imports (via forward adj)
    for exec_path in exec_files:
        reachable = _reachable_from(exec_path, forward_adj, max_depth=2)
        for data_path in data_files:
            if data_path == exec_path:
                continue
            if data_path in reachable:
                # Check we haven't already found this pair
                existing = {(l.data_file, l.exec_file) for l in graph.leads}
                if (data_path, exec_path) in existing:
                    continue
                depth = reachable[data_path]
                data_rec = file_by_path.get(data_path)
                exec_rec = file_by_path.get(exec_path)
                if not data_rec or not exec_rec:
                    continue
                data_indicators = [o.category for o in data_rec.observations if o.category in DATA_CATEGORIES]
                exec_indicators = [o.category for o in exec_rec.observations if o.category in EXEC_CATEGORIES]
                graph.leads.append(CrossFileLead(
                    data_file=data_path,
                    exec_file=exec_path,
                    connection="reverse-ref" if depth == 1 else f"reverse-transitive (depth {depth})",
                    data_indicators=data_indicators,
                    exec_indicators=exec_indicators,
                    severity=ObservationSeverity.HIGH if depth == 1 else ObservationSeverity.MEDIUM,
                    explanation=f"Exec-capable {exec_path} references encoded data in {data_path}.",
                ))

    # Safety net: high lead count suggests a security/crypto library, not split payloads.
    # Real attacks have 1-5 focused leads, not 20+.
    if len(graph.leads) > 20:
        logger.info("High lead count (%d) suggests security library; downgrading to MEDIUM", len(graph.leads))
        for lead in graph.leads:
            if lead.severity == ObservationSeverity.HIGH:
                lead.severity = ObservationSeverity.MEDIUM

    logger.info(
        "Reference graph: %d refs, %d leads, %d entry points, %d manifests, %d build files",
        len(graph.references), len(graph.leads), len(graph.entry_points),
        len(graph.manifests), len(graph.build_files),
    )
    return graph


def graph_to_observations(graph: ReferenceGraph) -> list[Observation]:
    obs: list[Observation] = []
    for lead in graph.leads:
        obs.append(Observation(
            source="cross-file-analysis",
            category="cross_file:data_exec_flow",
            severity=lead.severity,
            message=lead.explanation,
            evidence={
                "data_file": lead.data_file,
                "exec_file": lead.exec_file,
                "connection": lead.connection,
                "data_indicators": lead.data_indicators,
                "exec_indicators": lead.exec_indicators,
            },
            tags=["cross-file", "split-payload"],
        ))
    return obs


# --- Internal helpers ---

def _parse_references(
    source_path: str, content: str, classification: FileClassification,
) -> list[FileReference]:
    refs: list[FileReference] = []
    lower = source_path.lower()

    if lower.endswith(".py"):
        for match in _PY_IMPORT_RE.finditer(content):
            module = match.group(1) or match.group(2)
            refs.append(FileReference(source_path, module, "import", context=match.group(0).strip()))
        for match in _PY_OPEN_RE.finditer(content):
            refs.append(FileReference(source_path, match.group(1), "open", context=match.group(0).strip()))
        for match in _PY_LOAD_FILE_RE.finditer(content):
            refs.append(FileReference(source_path, match.group(1), "open", context=match.group(0).strip()))
        for match in _PY_EXEC_OPEN_RE.finditer(content):
            refs.append(FileReference(source_path, match.group(1), "exec_open", context=match.group(0).strip()))

    elif lower.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
        for match in _JS_REQUIRE_RE.finditer(content):
            refs.append(FileReference(source_path, match.group(1), "require", context=match.group(0).strip()))
        for match in _JS_IMPORT_RE.finditer(content):
            refs.append(FileReference(source_path, match.group(1), "import", context=match.group(0).strip()))
        for match in _JS_READFILE_RE.finditer(content):
            refs.append(FileReference(source_path, match.group(1), "open", context=match.group(0).strip()))

    return refs


def _resolve_path(
    target: str, source_path: str, known_paths: set[str], repo_path: Path,
) -> str | None:
    """Resolve a reference target to an actual file path in the repo."""
    source_dir = str(Path(source_path).parent)

    # Python module: foo.bar -> foo/bar.py or foo/bar/__init__.py
    if "." in target and "/" not in target and not target.startswith("."):
        module_path = target.replace(".", "/")
        for suffix in (".py", "/__init__.py"):
            candidate = module_path + suffix
            if candidate in known_paths:
                return candidate

    # Relative path: ./foo or ../foo
    if target.startswith("."):
        try:
            abs_source = repo_path / source_dir
            resolved = str((abs_source / target).resolve().relative_to(repo_path.resolve()))
        except ValueError:
            return None
        for suffix in ("", ".py", ".js", ".ts", "/index.js", "/index.ts"):
            candidate = resolved + suffix
            if candidate in known_paths:
                return candidate

    # Direct path
    if target in known_paths:
        return target

    # With extensions
    for suffix in (".py", ".js", ".ts", ".json"):
        if target + suffix in known_paths:
            return target + suffix

    return None


def _build_adjacency(
    references: list[FileReference], reverse: bool = False,
) -> dict[str, set[str]]:
    adj: dict[str, set[str]] = {}
    for ref in references:
        src = ref.target_path if reverse else ref.source_path
        tgt = ref.source_path if reverse else ref.target_path
        adj.setdefault(src, set()).add(tgt)
    return adj


def _reachable_from(
    start: str, adjacency: dict[str, set[str]], max_depth: int,
) -> dict[str, int]:
    """BFS from start, returns {path: depth} for all reachable nodes."""
    visited: dict[str, int] = {}
    frontier = [start]
    depth = 0
    while frontier and depth < max_depth:
        depth += 1
        next_frontier = []
        for node in frontier:
            for neighbor in adjacency.get(node, set()):
                if neighbor not in visited and neighbor != start:
                    visited[neighbor] = depth
                    next_frontier.append(neighbor)
        frontier = next_frontier
    return visited
