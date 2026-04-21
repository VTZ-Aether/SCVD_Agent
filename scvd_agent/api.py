from __future__ import annotations

from pathlib import Path
from typing import Any

from .io_contracts import build_io_envelope
from .orchestrator import ArithmeticAuditAgent
from .reporting import write_json_report, write_markdown_report
from .schemas import ScanArtifacts, ScanRequest


def scan_contract_project(request_data: dict[str, Any], *, base_dir: str | Path | None = None) -> dict[str, Any]:
    """Programmatic API for embedding the scanner in another agent or service."""
    request = ScanRequest.from_dict(request_data).resolve(base_dir)
    agent = ArithmeticAuditAgent(options=request.options)
    memory = agent.run(
        request.target,
        document_paths=request.documents,
        scope_files=request.scope_files,
    )

    out_dir = Path(request.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = out_dir / f"{request.report_prefix}.md" if "markdown" in request.output_formats else None
    json_path = out_dir / f"{request.report_prefix}.json" if "json" in request.output_formats else None
    artifacts = ScanArtifacts(
        markdown_report=str(markdown_path) if markdown_path is not None else None,
        json_report=str(json_path) if json_path is not None else None,
    )
    envelope = build_io_envelope(request=request, artifacts=artifacts, memory=memory)
    envelope_dict = envelope.to_dict()

    if markdown_path is not None:
        write_markdown_report(memory, markdown_path)
    if json_path is not None:
        write_json_report(memory, json_path, envelope=envelope_dict)

    return envelope_dict
