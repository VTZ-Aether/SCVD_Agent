from __future__ import annotations

import re
from pathlib import Path

from .knowledge import STATE_SENSITIVE_VARIABLES, VALUATION_KEYWORDS, WORKFLOW_KEYWORDS
from .models import CallGraphEdge, DocumentChunk, InheritanceEdge, ProjectProfile, WorkingMemory
from .parser import discover_document_chunks, parse_project


CONTRACT_INHERITANCE_RE = re.compile(
    r"\b(?:abstract\s+contract|contract|interface)\s+([A-Za-z_]\w*)\s*(?:is\s+([^{]+))?\{"
)


class ProjectProfilerAgent:
    """Project/document intake module: indexes contracts, docs, functions, and state."""

    def run(self, target_path: Path, *, document_paths: list[Path] | None = None) -> WorkingMemory:
        source_files, state_vars_by_file, functions = parse_project(target_path)
        documents = discover_document_chunks(target_path)
        documents.extend(_discover_extra_documents(document_paths or []))
        profile = ProjectProfile(root=str(target_path))
        profile.contract_files = [source_file.path for source_file in source_files]
        profile.languages = {source_file.language for source_file in source_files}
        profile.protocol_keywords = {
            keyword
            for function in functions
            for keyword in function.economic_keywords
            if keyword in WORKFLOW_KEYWORDS or keyword in VALUATION_KEYWORDS
        }
        profile.economic_state_vars = {
            variable
            for variables in state_vars_by_file.values()
            for variable in variables
            if any(hint in variable.lower() for hint in STATE_SENSITIVE_VARIABLES)
        }
        memory = WorkingMemory(
            profile=profile,
            source_files=source_files,
            documents=documents,
            state_vars_by_file=state_vars_by_file,
            functions=functions,
        )
        memory.notes.append(
            f"ProjectProfilerAgent indexed {len(source_files)} contract files, "
            f"{len(documents)} documentation chunks, and {len(functions)} functions."
        )
        return memory


class CodeStructureAgent:
    """Blue-box extractor: function calls, inheritance relations, and state surface."""

    def run(self, memory: WorkingMemory) -> None:
        memory.call_edges = _build_call_edges(memory)
        memory.inheritance_edges = _build_inheritance_edges(memory)
        memory.notes.append(
            f"CodeStructureAgent extracted {len(memory.call_edges)} call edges, "
            f"{len(memory.inheritance_edges)} inheritance edges, and "
            f"{sum(len(items) for items in memory.state_vars_by_file.values())} state variables."
        )


def _build_call_edges(memory: WorkingMemory) -> list[CallGraphEdge]:
    functions_by_name: dict[str, list[str]] = {}
    for function in memory.functions:
        functions_by_name.setdefault(function.name, []).append(function.qualified_name)

    edges: list[CallGraphEdge] = []
    seen: set[tuple[str, str]] = set()
    for function in memory.functions:
        for call in sorted(function.calls):
            callees = functions_by_name.get(call)
            if not callees:
                continue
            for callee in callees:
                if callee == function.qualified_name:
                    continue
                key = (function.qualified_name, callee)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(
                    CallGraphEdge(
                        caller=function.qualified_name,
                        callee=callee,
                        call_type="project_function",
                        confidence=0.75,
                    )
                )
    return edges


def _build_inheritance_edges(memory: WorkingMemory) -> list[InheritanceEdge]:
    edges: list[InheritanceEdge] = []
    for source_file in memory.source_files:
        if source_file.language != "solidity":
            continue
        for match in CONTRACT_INHERITANCE_RE.finditer(source_file.text):
            child = match.group(1)
            parents = match.group(2)
            if not parents:
                continue
            line_number = source_file.text.count("\n", 0, match.start()) + 1
            for raw_parent in parents.split(","):
                parent = raw_parent.strip().split("(", 1)[0].strip()
                if not parent:
                    continue
                edges.append(
                    InheritanceEdge(
                        child=child,
                        parent=parent,
                        path=source_file.path,
                        line_number=line_number,
                    )
                )
    return edges


def _discover_extra_documents(paths: list[Path]) -> list[DocumentChunk]:
    chunks: list[DocumentChunk] = []
    seen_paths: set[str] = set()
    for path in paths:
        resolved = path.resolve()
        if not resolved.exists():
            continue
        if resolved.is_dir():
            for chunk in discover_document_chunks(resolved):
                if chunk.path in seen_paths:
                    continue
                seen_paths.add(chunk.path)
                chunks.append(chunk)
            continue
        if resolved.suffix.lower() not in {".md", ".rst", ".txt"}:
            continue
        text = resolved.read_text(encoding="utf-8", errors="ignore").strip()
        if not text:
            continue
        seen_paths.add(str(resolved))
        chunks.append(
            DocumentChunk(
                path=str(resolved),
                title=resolved.name,
                text=text[:4000],
            )
        )
    return chunks
