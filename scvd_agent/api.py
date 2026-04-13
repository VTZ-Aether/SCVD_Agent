from __future__ import annotations

from pathlib import Path
from typing import Any

from .orchestrator import ArithmeticAuditAgent
from .reporting import write_json_report, write_markdown_report
from .schemas import ScanArtifacts, ScanRequest


def scan_contract_project(request_data: dict[str, Any], *, base_dir: str | Path | None = None) -> dict[str, Any]:
    """Programmatic API for embedding the scanner in another agent or service."""
    request = ScanRequest.from_dict(request_data).resolve(base_dir)
    agent = ArithmeticAuditAgent(options=request.options)
    memory = agent.run(request.target)

    out_dir = Path(request.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = out_dir / f"{request.report_prefix}.md"
    json_path = out_dir / f"{request.report_prefix}.json"
    write_markdown_report(memory, markdown_path)
    write_json_report(memory, json_path)

    return {
        "request": request.to_dict(),
        "artifacts": ScanArtifacts(
            markdown_report=str(markdown_path),
            json_report=str(json_path),
        ).to_dict(),
        "result": memory.to_dict(),
    }
