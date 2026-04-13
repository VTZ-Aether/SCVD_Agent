from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(slots=True)
class SourceLocation:
    path: str
    start_line: int
    end_line: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SourceFile:
    path: str
    language: str
    text: str


@dataclass(slots=True)
class DocumentChunk:
    path: str
    title: str
    text: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuditKnowledgeRecord:
    id: str
    title: str
    source: str
    category: str
    severity_hint: str
    semantics: list[str] = field(default_factory=list)
    vulnerability_patterns: list[str] = field(default_factory=list)
    detection_cues: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RetrievedKnowledge:
    knowledge_id: str
    score: float
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "knowledge_id": self.knowledge_id,
            "score": round(self.score, 3),
            "rationale": self.rationale,
        }


@dataclass(slots=True)
class ArithmeticSite:
    line_number: int
    code: str
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FunctionFact:
    name: str
    file_path: str
    language: str
    start_line: int
    end_line: int
    source: str
    decorators: list[str] = field(default_factory=list)
    state_reads: set[str] = field(default_factory=set)
    state_writes: set[str] = field(default_factory=set)
    local_assignments: set[str] = field(default_factory=set)
    arithmetic_sites: list[ArithmeticSite] = field(default_factory=list)
    calls: set[str] = field(default_factory=set)
    loop_count: int = 0
    economic_keywords: set[str] = field(default_factory=set)
    precision_markers: set[str] = field(default_factory=set)
    branch_markers: set[str] = field(default_factory=set)
    risky_markers: set[str] = field(default_factory=set)
    guards: set[str] = field(default_factory=set)
    score: float = 0.0

    @property
    def qualified_name(self) -> str:
        return f"{self.file_path}:{self.name}"

    @property
    def location(self) -> SourceLocation:
        return SourceLocation(
            path=self.file_path,
            start_line=self.start_line,
            end_line=self.end_line,
        )

    @property
    def has_division(self) -> bool:
        return any("division" in site.tags for site in self.arithmetic_sites)

    @property
    def has_floor_rounding(self) -> bool:
        return any("floorish" in site.tags for site in self.arithmetic_sites)

    @property
    def has_explicit_rounding_control(self) -> bool:
        return any(
            tag in {"round_up", "round_down", "explicit_rounding"}
            for site in self.arithmetic_sites
            for tag in site.tags
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state_reads"] = sorted(self.state_reads)
        data["state_writes"] = sorted(self.state_writes)
        data["local_assignments"] = sorted(self.local_assignments)
        data["calls"] = sorted(self.calls)
        data["economic_keywords"] = sorted(self.economic_keywords)
        data["precision_markers"] = sorted(self.precision_markers)
        data["branch_markers"] = sorted(self.branch_markers)
        data["risky_markers"] = sorted(self.risky_markers)
        data["guards"] = sorted(self.guards)
        return data


@dataclass(slots=True)
class WorkflowEdge:
    variable: str
    writer: str
    reader: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BusinessFlow:
    id: str
    name: str
    category: str
    entry_points: list[str] = field(default_factory=list)
    state_variables: list[str] = field(default_factory=list)
    upstream: list[str] = field(default_factory=list)
    downstream: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuditTask:
    id: str
    flow_id: str
    knowledge_id: str
    semantic: str
    vulnerability_pattern: str
    priority: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BusinessConstraint:
    id: str
    title: str
    flow_id: str
    knowledge_id: str
    invariant_type: str
    expression: str
    severity_hint: str
    status: str
    rationale: str
    evidence: list[str] = field(default_factory=list)
    related_functions: list[str] = field(default_factory=list)
    locations: list[SourceLocation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "flow_id": self.flow_id,
            "knowledge_id": self.knowledge_id,
            "invariant_type": self.invariant_type,
            "expression": self.expression,
            "severity_hint": self.severity_hint,
            "status": self.status,
            "rationale": self.rationale,
            "evidence": self.evidence,
            "related_functions": self.related_functions,
            "locations": [location.to_dict() for location in self.locations],
        }


@dataclass(slots=True)
class ValidationResult:
    finding_id: str
    status: str
    confidence: float
    rationale: str
    validation_level: str = "static"
    preconditions: list[str] = field(default_factory=list)
    false_positive_checks: list[str] = field(default_factory=list)
    attack_path: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "status": self.status,
            "confidence": round(self.confidence, 3),
            "rationale": self.rationale,
            "validation_level": self.validation_level,
            "preconditions": self.preconditions,
            "false_positive_checks": self.false_positive_checks,
            "attack_path": self.attack_path,
            "next_steps": self.next_steps,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str
    confidence: float
    summary: str
    rationale: str
    evidence: list[str]
    locations: list[SourceLocation]
    tags: list[str] = field(default_factory=list)
    related_functions: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "summary": self.summary,
            "rationale": self.rationale,
            "evidence": self.evidence,
            "locations": [loc.to_dict() for loc in self.locations],
            "tags": self.tags,
            "related_functions": self.related_functions,
            "remediation": self.remediation,
        }


@dataclass(slots=True)
class ProjectProfile:
    root: str
    languages: set[str] = field(default_factory=set)
    contract_files: list[str] = field(default_factory=list)
    protocol_keywords: set[str] = field(default_factory=set)
    economic_state_vars: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "languages": sorted(self.languages),
            "contract_files": self.contract_files,
            "protocol_keywords": sorted(self.protocol_keywords),
            "economic_state_vars": sorted(self.economic_state_vars),
        }


@dataclass(slots=True)
class WorkingMemory:
    profile: ProjectProfile
    source_files: list[SourceFile] = field(default_factory=list)
    documents: list[DocumentChunk] = field(default_factory=list)
    knowledge_base: list[AuditKnowledgeRecord] = field(default_factory=list)
    retrieved_knowledge: list[RetrievedKnowledge] = field(default_factory=list)
    state_vars_by_file: dict[str, set[str]] = field(default_factory=dict)
    functions: list[FunctionFact] = field(default_factory=list)
    business_flows: list[BusinessFlow] = field(default_factory=list)
    audit_tasks: list[AuditTask] = field(default_factory=list)
    business_constraints: list[BusinessConstraint] = field(default_factory=list)
    hotspots: list[FunctionFact] = field(default_factory=list)
    workflow_edges: list[WorkflowEdge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    validation_results: list[ValidationResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.to_dict(),
            "source_files": [file.path for file in self.source_files],
            "documents": [document.to_dict() for document in self.documents],
            "knowledge_base": [record.to_dict() for record in self.knowledge_base],
            "retrieved_knowledge": [item.to_dict() for item in self.retrieved_knowledge],
            "state_vars_by_file": {
                path: sorted(vars_) for path, vars_ in self.state_vars_by_file.items()
            },
            "functions": [function.to_dict() for function in self.functions],
            "business_flows": [flow.to_dict() for flow in self.business_flows],
            "audit_tasks": [task.to_dict() for task in self.audit_tasks],
            "business_constraints": [constraint.to_dict() for constraint in self.business_constraints],
            "hotspots": [hotspot.to_dict() for hotspot in self.hotspots],
            "workflow_edges": [edge.to_dict() for edge in self.workflow_edges],
            "findings": [finding.to_dict() for finding in self.findings],
            "validation_results": [result.to_dict() for result in self.validation_results],
            "notes": self.notes,
        }
