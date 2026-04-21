from __future__ import annotations

import hashlib

from .agents import (
    HotspotExtractionAgent,
    HypothesisAgent,
    ReflectionAgent,
    VulnerabilityReasoningAgent,
    WorkflowMapperAgent,
)
from .knowledge import knowledge_by_id
from .models import Finding, RootCauseAnalysis, WorkingMemory
from .rag_agents import attack_poc_by_id


class RootCauseReasoningAgent:
    """LLM3 role: derive vulnerability root causes from findings plus both RAG stores."""

    def run(self, memory: WorkingMemory) -> None:
        audit_records = knowledge_by_id(memory.knowledge_base)
        attack_records = attack_poc_by_id(memory.attack_poc_knowledge_base)
        retrieved_attack_ids = [item.poc_id for item in memory.retrieved_attack_pocs]
        root_causes: list[RootCauseAnalysis] = []

        for finding in memory.findings:
            category = _finding_category(finding)
            audit_ids = [
                record_id
                for record_id, record in audit_records.items()
                if record.category == category or record.category in finding.tags
            ][:3]
            attack_ids = [
                poc_id
                for poc_id in retrieved_attack_ids
                if attack_records.get(poc_id) is not None
                and (attack_records[poc_id].category == category or attack_records[poc_id].category in finding.tags)
            ][:3]
            root_causes.append(
                RootCauseAnalysis(
                    id=_make_id(finding.id, "root_cause"),
                    finding_id=finding.id,
                    category=category,
                    root_cause=_root_cause_text(finding, attack_ids),
                    evidence=finding.evidence[:5],
                    audit_knowledge_ids=audit_ids,
                    attack_poc_ids=attack_ids,
                )
            )

        memory.root_causes = root_causes
        memory.notes.append(
            f"RootCauseReasoningAgent derived {len(root_causes)} root-cause records using audit and attack PoC RAG context."
        )


def _finding_category(finding: Finding) -> str:
    for candidate in (
        "accounting",
        "arithmetic",
        "oracle",
        "access-control",
        "reentrancy",
        "external-call",
        "signature",
        "dos",
        "upgradeability",
    ):
        if candidate in finding.tags:
            return candidate
    if "business_constraint" in finding.tags:
        return "business_constraint"
    return finding.tags[0] if finding.tags else "unknown"


def _root_cause_text(finding: Finding, attack_poc_ids: list[str]) -> str:
    support = f" Historical PoC analogues: {', '.join(attack_poc_ids)}." if attack_poc_ids else ""
    return f"{finding.rationale} The vulnerable behavior is summarized as: {finding.summary}.{support}"


def _make_id(seed: str, suffix: str) -> str:
    digest = hashlib.sha1(f"{seed}:{suffix}".encode("utf-8")).hexdigest()[:10]
    return f"{suffix}-{digest}"
