from __future__ import annotations

import re
from pathlib import Path

from .knowledge import (
    ECONOMIC_KEYWORDS,
    PRECISION_MARKERS,
    RISKY_MARKERS,
    ROUNDING_DOWN_MARKERS,
    ROUNDING_UP_MARKERS,
    VALUATION_KEYWORDS,
    WORKFLOW_KEYWORDS,
)
from .models import ArithmeticSite, FunctionFact, SourceFile
from .models import DocumentChunk


SUPPORTED_EXTENSIONS = {
    ".sol": "solidity",
    ".vy": "vyper",
}

SUPPORTED_DOCUMENT_EXTENSIONS = {
    ".md",
    ".rst",
    ".txt",
}

DOCUMENT_SKIP_DIRS = {
    ".git",
    ".idea",
    "artifacts",
    "broadcast",
    "cache",
    "lib",
    "node_modules",
    "out",
    "reports",
}


STATE_VAR_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+\)|[A-Za-z_]\w*(?:\s*\[[^\]]*\])*)\s+"
    r"(?:(?:public|private|internal|external|constant|immutable|override|payable)\s+)*"
    r"([A-Za-z_]\w*)\s*(?:=.*)?;"
)

VYPER_STATE_VAR_RE = re.compile(
    r"^\s*([A-Za-z_]\w*)\s*:\s*(?!event\b)(?!interface\b)(?!struct\b)(?!flag\b).+$"
)

SOLIDITY_FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
SOLIDITY_CONSTRUCTOR_RE = re.compile(r"\bconstructor\s*\(")
VYPER_FUNCTION_RE = re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)

CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
WRITE_RE = re.compile(r"(?:self\.)?([A-Za-z_]\w*)\s*(?:\[[^\]]+\])?\s*[-+*/%]?=")
TOKEN_RE = re.compile(r"\b[A-Za-z_]\w*\b")
REQUIRE_RE = re.compile(r"\b(?:require|assert|if)\s*\(([^)]*)\)")


def discover_source_files(root: Path) -> list[SourceFile]:
    source_files: list[SourceFile] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        language = SUPPORTED_EXTENSIONS.get(path.suffix.lower())
        if language is None:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        source_files.append(SourceFile(path=str(path), language=language, text=text))
    return source_files


def discover_document_chunks(root: Path, *, max_chars_per_chunk: int = 4000) -> list[DocumentChunk]:
    chunks: list[DocumentChunk] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in DOCUMENT_SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SUPPORTED_DOCUMENT_EXTENSIONS:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if not text.strip():
            continue
        chunks.extend(_chunk_document(path, text, max_chars_per_chunk=max_chars_per_chunk))
    return chunks


def _chunk_document(path: Path, text: str, *, max_chars_per_chunk: int) -> list[DocumentChunk]:
    sections: list[tuple[str, list[str]]] = []
    current_title = path.name
    current_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            if current_lines:
                sections.append((current_title, current_lines))
                current_lines = []
            current_title = line.lstrip("#").strip() or path.name
        current_lines.append(line)
    if current_lines:
        sections.append((current_title, current_lines))

    chunks: list[DocumentChunk] = []
    for title, lines in sections:
        section_text = "\n".join(lines).strip()
        if not section_text:
            continue
        for index in range(0, len(section_text), max_chars_per_chunk):
            text_slice = section_text[index:index + max_chars_per_chunk]
            chunk_title = title if index == 0 else f"{title} (part {index // max_chars_per_chunk + 1})"
            chunks.append(
                DocumentChunk(
                    path=str(path),
                    title=chunk_title,
                    text=text_slice,
                )
            )
    return chunks


def parse_project(root: Path) -> tuple[list[SourceFile], dict[str, set[str]], list[FunctionFact]]:
    source_files = discover_source_files(root)
    state_vars_by_file: dict[str, set[str]] = {}
    functions: list[FunctionFact] = []

    for source_file in source_files:
        if source_file.language == "solidity":
            state_vars = _extract_solidity_state_vars(source_file.text)
            file_functions = _extract_solidity_functions(source_file.path, source_file.text, state_vars)
        else:
            state_vars = _extract_vyper_state_vars(source_file.text)
            file_functions = _extract_vyper_functions(source_file.path, source_file.text, state_vars)

        state_vars_by_file[source_file.path] = state_vars
        functions.extend(file_functions)

    return source_files, state_vars_by_file, functions


def _extract_solidity_state_vars(text: str) -> set[str]:
    state_vars: set[str] = set()
    lines = text.splitlines()
    brace_depth = 0
    for line in lines:
        stripped = line.split("//", 1)[0]
        if brace_depth <= 1:
            match = STATE_VAR_RE.match(stripped)
            if match:
                state_vars.add(match.group(1))
        brace_depth += stripped.count("{")
        brace_depth -= stripped.count("}")
    return state_vars


def _extract_vyper_state_vars(text: str) -> set[str]:
    state_vars: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("@") or stripped.startswith("def "):
            continue
        match = VYPER_STATE_VAR_RE.match(line)
        if match:
            state_vars.add(match.group(1))
    return state_vars


def _extract_solidity_functions(path: str, text: str, state_vars: set[str]) -> list[FunctionFact]:
    functions: list[FunctionFact] = []
    for match in list(SOLIDITY_FUNCTION_RE.finditer(text)) + list(SOLIDITY_CONSTRUCTOR_RE.finditer(text)):
        name = match.group(1) if match.re is SOLIDITY_FUNCTION_RE else "constructor"
        brace_index = text.find("{", match.end())
        if brace_index == -1:
            continue
        end_index = _find_matching_brace(text, brace_index)
        if end_index == -1:
            continue
        source = text[match.start(): end_index + 1]
        start_line = text.count("\n", 0, match.start()) + 1
        end_line = text.count("\n", 0, end_index) + 1
        functions.append(
            _analyze_function(
                name=name,
                path=path,
                language="solidity",
                source=source,
                start_line=start_line,
                end_line=end_line,
                state_vars=state_vars,
            )
        )
    return functions


def _extract_vyper_functions(path: str, text: str, state_vars: set[str]) -> list[FunctionFact]:
    functions: list[FunctionFact] = []
    lines = text.splitlines()
    matches = list(VYPER_FUNCTION_RE.finditer(text))
    offsets: list[int] = []
    acc = 0
    for line in lines:
        offsets.append(acc)
        acc += len(line) + 1

    for match in matches:
        start_line = text.count("\n", 0, match.start()) + 1
        start_index = offsets[start_line - 1]
        indent = len(lines[start_line - 1]) - len(lines[start_line - 1].lstrip())
        end_line = len(lines)
        for idx in range(start_line, len(lines)):
            line = lines[idx]
            if not line.strip():
                continue
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= indent and not line.lstrip().startswith("@"):
                end_line = idx
                break
        source = "\n".join(lines[start_line - 1:end_line])
        functions.append(
            _analyze_function(
                name=match.group(1),
                path=path,
                language="vyper",
                source=source,
                start_line=start_line,
                end_line=end_line,
                state_vars=state_vars,
            )
        )
    return functions


def _find_matching_brace(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _analyze_function(
    *,
    name: str,
    path: str,
    language: str,
    source: str,
    start_line: int,
    end_line: int,
    state_vars: set[str],
) -> FunctionFact:
    lower_source = source.lower()
    tokens = {token.lower() for token in TOKEN_RE.findall(source)}
    economic_keywords = {
        keyword
        for keyword in ECONOMIC_KEYWORDS
        if keyword in lower_source or keyword in name.lower()
    } | (tokens & ECONOMIC_KEYWORDS)
    precision_markers = {marker for marker in PRECISION_MARKERS if marker in lower_source}
    risky_markers = {marker for marker in RISKY_MARKERS if marker in lower_source}

    arithmetic_sites: list[ArithmeticSite] = []
    for offset, raw_line in enumerate(source.splitlines(), start=0):
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if not _looks_like_arithmetic(line):
            continue

        line_tags: list[str] = []
        lower_line = line.lower()
        if "/" in line or "div" in lower_line:
            line_tags.append("division")
            if "muldivup" not in lower_line and "roundup" not in lower_line and "ceildiv" not in lower_line:
                line_tags.append("floorish")
        if "*" in line or "mul" in lower_line:
            line_tags.append("multiplication")
        if any(marker in lower_line for marker in ROUNDING_UP_MARKERS):
            line_tags.extend(["round_up", "explicit_rounding"])
        if any(marker in lower_line for marker in ROUNDING_DOWN_MARKERS):
            line_tags.extend(["round_down", "explicit_rounding"])
        if " min(" in f" {lower_line}" or " max(" in f" {lower_line}" or "?" in line:
            line_tags.append("branch")
        if any(keyword in lower_line for keyword in VALUATION_KEYWORDS):
            line_tags.append("valuation")

        arithmetic_sites.append(
            ArithmeticSite(
                line_number=start_line + offset,
                code=line.strip(),
                tags=line_tags,
            )
        )

    identifiers = set(TOKEN_RE.findall(source))
    state_reads = state_vars & identifiers
    state_writes = {
        variable
        for variable in WRITE_RE.findall(source)
        if variable in state_vars
    }
    local_assignments = set(WRITE_RE.findall(source)) - state_writes

    calls = {
        call
        for call in CALL_RE.findall(source)
        if call not in {"if", "for", "while", "return", "require", "assert"}
    }

    guards = _extract_guards(source, state_vars)
    branch_markers = set()
    if " min(" in f" {lower_source}" or " max(" in f" {lower_source}" or "?" in source:
        branch_markers.add("regime_switch")
    if any(keyword in lower_source for keyword in VALUATION_KEYWORDS):
        branch_markers.add("valuation_path")

    loop_count = len(re.findall(r"\b(?:for|while)\b", source))

    score = (
        len(arithmetic_sites) * 1.5
        + len(economic_keywords) * 1.2
        + len(state_reads | state_writes) * 0.7
        + loop_count * 0.8
        + len(branch_markers) * 1.0
        + len(risky_markers) * 1.5
    )

    return FunctionFact(
        name=name,
        file_path=path,
        language=language,
        start_line=start_line,
        end_line=end_line,
        source=source,
        state_reads=state_reads,
        state_writes=state_writes,
        local_assignments=local_assignments,
        arithmetic_sites=arithmetic_sites,
        calls=calls,
        loop_count=loop_count,
        economic_keywords=economic_keywords,
        precision_markers=precision_markers,
        branch_markers=branch_markers,
        risky_markers=risky_markers,
        guards=guards,
        score=score,
    )


def _extract_guards(source: str, state_vars: set[str]) -> set[str]:
    guards: set[str] = set()
    lower_source = source.lower()
    for variable in state_vars:
        if variable.lower() not in lower_source:
            continue
        if re.search(rf"\b{re.escape(variable)}\b\s*(?:==|!=|>|<|>=|<=)\s*0", source):
            guards.add(variable)
    for match in REQUIRE_RE.finditer(source):
        condition = match.group(1)
        for variable in state_vars:
            if variable in condition and "0" in condition:
                guards.add(variable)
    return guards


def _looks_like_arithmetic(line: str) -> bool:
    lowered = line.lower()
    if lowered.startswith(("event ", "modifier ", "error ")):
        return False
    return any(marker in line for marker in ("+", "-", "*", "/", "%")) or any(
        token in lowered
        for token in (
            "muldiv",
            "ceildiv",
            "unsafe_div",
            "unsafe_mul",
            "unsafe_sub",
            "unsafe_add",
            "mulwad",
            "divwad",
        )
    )
