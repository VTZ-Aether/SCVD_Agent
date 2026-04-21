from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Any

from .models import WorkingMemory
from .schemas import ScanArtifacts, ScanRequest


SCVD_IO_SCHEMA_VERSION = "scvd.multiagent.io.v1"


INPUT_CONTRACT: dict[str, Any] = {
    "schema_version": SCVD_IO_SCHEMA_VERSION,
    "required": {
        "target": "Absolute or request-relative path to a Solidity/Vyper project or directory.",
    },
    "optional": {
        "documents": "Additional Markdown/RST/TXT documentation paths to include as protocol context.",
        "scope_files": "Specific contract files to prioritize while still allowing dependency context.",
        "audit_sources": "Audit-report RAG source labels. Default: code4rena, sherlock.",
        "attack_sources": "Historical attack PoC RAG source labels. Default: defihack.",
        "out_dir": "Report output directory.",
        "report_prefix": "Report filename prefix.",
        "output_formats": "Any of: markdown, json.",
        "options": "Agent limits and optional LLM configuration.",
    },
}


OUTPUT_CONTRACT: dict[str, Any] = {
    "schema_version": SCVD_IO_SCHEMA_VERSION,
    "top_level_keys": {
        "schema_version": "Stable IO contract version.",
        "inputs": "Normalized resolved ScanRequest.",
        "artifacts": "Paths to generated report files.",
        "summary": "Compact counts and status summaries for UI/agent routing.",
        "outputs": "Stable high-value outputs grouped by workflow module.",
        "working_memory": "Full internal working memory for advanced downstream agents.",
    },
    "outputs": {
        "project": "Profile, code structure, and business logic units.",
        "rag": "Retrieved audit-report records and historical attack PoC records.",
        "analysis": "Constraints, findings, validation results, and root causes.",
        "poc": "PoC drafts and Foundry sandbox feedback.",
        "patches": "Patch candidates, dynamic validation plans, and security patch plans.",
    },
}


@dataclass(slots=True)
class OutputSummary:
    findings: int
    by_severity: dict[str, int] = field(default_factory=dict)
    validation_statuses: dict[str, int] = field(default_factory=dict)
    root_causes: int = 0
    poc_drafts: int = 0
    patch_candidates: int = 0
    security_patches: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FrameworkIOEnvelope:
    schema_version: str
    inputs: dict[str, Any]
    artifacts: dict[str, Any]
    summary: OutputSummary
    outputs: dict[str, Any]
    working_memory: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "input_contract": INPUT_CONTRACT,
            "output_contract": OUTPUT_CONTRACT,
            "inputs": self.inputs,
            "artifacts": self.artifacts,
            "summary": self.summary.to_dict(),
            "outputs": self.outputs,
            "working_memory": self.working_memory,
        }


def build_output_summary(memory: WorkingMemory) -> OutputSummary:
    return OutputSummary(
        findings=len(memory.findings),
        by_severity=dict(Counter(finding.severity for finding in memory.findings)),
        validation_statuses=dict(Counter(result.status for result in memory.validation_results)),
        root_causes=len(memory.root_causes),
        poc_drafts=len(memory.poc_drafts),
        patch_candidates=len(memory.patch_candidates),
        security_patches=len(memory.security_patches),
        notes=memory.notes,
    )


def build_stable_outputs(memory: WorkingMemory) -> dict[str, Any]:
    return {
        "project": {
            "profile": memory.profile.to_dict(),
            "source_files": [file.path for file in memory.source_files],
            "documents": [document.to_dict() for document in memory.documents],
            "call_edges": [edge.to_dict() for edge in memory.call_edges],
            "inheritance_edges": [edge.to_dict() for edge in memory.inheritance_edges],
            "business_flows": [flow.to_dict() for flow in memory.business_flows],
            "business_logic_units": [unit.to_dict() for unit in memory.business_logic_units],
        },
        "rag": {
            "audit_knowledge": [item.to_dict() for item in memory.retrieved_knowledge],
            "attack_pocs": [item.to_dict() for item in memory.retrieved_attack_pocs],
        },
        "analysis": {
            "business_constraints": [constraint.to_dict() for constraint in memory.business_constraints],
            "findings": [finding.to_dict() for finding in memory.findings],
            "validation_results": [result.to_dict() for result in memory.validation_results],
            "root_causes": [root_cause.to_dict() for root_cause in memory.root_causes],
        },
        "poc": {
            "drafts": [draft.to_dict() for draft in memory.poc_drafts],
            "foundry_results": [result.to_dict() for result in memory.foundry_results],
        },
        "patches": {
            "patch_candidates": [candidate.to_dict() for candidate in memory.patch_candidates],
            "dynamic_validation_results": [result.to_dict() for result in memory.dynamic_validation_results],
            "security_patches": [patch.to_dict() for patch in memory.security_patches],
        },
    }


def build_io_envelope(
    *,
    request: ScanRequest,
    artifacts: ScanArtifacts,
    memory: WorkingMemory,
) -> FrameworkIOEnvelope:
    return FrameworkIOEnvelope(
        schema_version=SCVD_IO_SCHEMA_VERSION,
        inputs=request.to_dict(),
        artifacts=artifacts.to_dict(),
        summary=build_output_summary(memory),
        outputs=build_stable_outputs(memory),
        working_memory=memory.to_dict(),
    )
