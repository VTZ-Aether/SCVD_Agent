from __future__ import annotations

from pathlib import Path

from .models import Finding, FunctionFact, WorkingMemory


def build_finding_context(memory: WorkingMemory, finding: Finding) -> str:
    functions = {
        function.qualified_name: function
        for function in memory.functions
    }
    blocks: list[str] = []
    blocks.append("# Finding")
    blocks.append(f"Title: {finding.title}")
    blocks.append(f"Severity: {finding.severity}")
    blocks.append(f"Summary: {finding.summary}")
    blocks.append("")
    blocks.append("# Evidence")
    blocks.extend(f"- {item}" for item in finding.evidence)
    blocks.append("")
    validations = {
        result.finding_id: result
        for result in memory.validation_results
    }
    validation = validations.get(finding.id)
    if validation is not None:
        blocks.append("# Step 4 validation plan")
        blocks.append(f"Status: {validation.status}")
        blocks.append(f"Level: {validation.validation_level}")
        blocks.append(f"Rationale: {validation.rationale}")
        blocks.append("Preconditions:")
        blocks.extend(f"- {item}" for item in validation.preconditions)
        blocks.append("False-positive checks:")
        blocks.extend(f"- {item}" for item in validation.false_positive_checks)
        blocks.append("Attack path:")
        blocks.extend(f"- {item}" for item in validation.attack_path)
        blocks.append("")
    blocks.append("# Retrieved audit knowledge")
    records = {record.id: record for record in memory.knowledge_base}
    for item in memory.retrieved_knowledge[:8]:
        record = records.get(item.knowledge_id)
        if record is None:
            continue
        blocks.append(
            f"- {record.id}: {record.title} ({record.category}, {record.severity_hint}); {item.rationale}"
        )
    blocks.append("")
    related = set(finding.related_functions)
    constraints = [
        constraint
        for constraint in memory.business_constraints
        if related & set(constraint.related_functions) or constraint.title in finding.title
    ]
    if constraints:
        blocks.append("# Business constraints")
        for constraint in constraints[:5]:
            blocks.append(
                f"- {constraint.status}: {constraint.title}; {constraint.expression}; {constraint.rationale}"
            )
        blocks.append("")
    blocks.append("# Related source")
    for name in finding.related_functions:
        function = functions.get(name)
        if function is None:
            continue
        blocks.append(_format_function(function))
    return "\n".join(blocks)


def _format_function(function: FunctionFact) -> str:
    path = Path(function.file_path).name
    return (
        f"## {path}:{function.name} ({function.start_line}-{function.end_line})\n"
        f"State reads: {', '.join(sorted(function.state_reads)) or 'N/A'}\n"
        f"State writes: {', '.join(sorted(function.state_writes)) or 'N/A'}\n"
        "```solidity\n"
        f"{function.source.strip()}\n"
        "```"
    )
