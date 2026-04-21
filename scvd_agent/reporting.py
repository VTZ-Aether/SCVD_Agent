from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .models import WorkingMemory


def write_json_report(memory: WorkingMemory, path: Path, *, envelope: dict[str, Any] | None = None) -> None:
    data = envelope if envelope is not None else memory.to_dict()
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def write_markdown_report(memory: WorkingMemory, path: Path) -> None:
    knowledge_records = {record.id: record for record in memory.knowledge_base}
    validations_by_finding = {
        result.finding_id: result for result in memory.validation_results
    }
    findings_by_id = {finding.id: finding for finding in memory.findings}
    lines: list[str] = []
    lines.append("# SCVD Agent Report")
    lines.append("")
    lines.append("## Project Summary")
    lines.append("")
    lines.append(f"- Root: `{memory.profile.root}`")
    lines.append(f"- Languages: {', '.join(sorted(memory.profile.languages)) or 'N/A'}")
    lines.append(f"- Contract files: {len(memory.profile.contract_files)}")
    lines.append(f"- Indexed functions: {len(memory.functions)}")
    lines.append(f"- Documentation chunks: {len(memory.documents)}")
    lines.append(f"- Retrieved knowledge records: {len(memory.retrieved_knowledge)}")
    lines.append(f"- Retrieved attack PoC records: {len(memory.retrieved_attack_pocs)}")
    lines.append(f"- Call graph edges: {len(memory.call_edges)}")
    lines.append(f"- Inheritance edges: {len(memory.inheritance_edges)}")
    lines.append(f"- Business flow nodes: {len(memory.business_flows)}")
    lines.append(f"- Business logic units: {len(memory.business_logic_units)}")
    lines.append(f"- Business constraints: {len(memory.business_constraints)}")
    lines.append(f"- Arithmetic hotspots: {len(memory.hotspots)}")
    lines.append(f"- Workflow edges: {len(memory.workflow_edges)}")
    lines.append(f"- Findings: {len(memory.findings)}")
    lines.append(f"- Validation results: {len(memory.validation_results)}")
    lines.append(f"- PoC drafts: {len(memory.poc_drafts)}")
    lines.append(f"- Patch candidates: {len(memory.patch_candidates)}")
    lines.append("")
    lines.append("## Agent Notes")
    lines.append("")
    for note in memory.notes:
        lines.append(f"- {note}")
    lines.append("")
    lines.append("## Retrieved Audit Knowledge")
    lines.append("")
    if not memory.retrieved_knowledge:
        lines.append("No audit knowledge records were retrieved.")
    for item in memory.retrieved_knowledge:
        record = knowledge_records.get(item.knowledge_id)
        if record is None:
            continue
        lines.append(
            f"- `{record.id}` ({record.source}, {record.severity_hint}): {record.title} "
            f"(score={item.score:.2f}; {item.rationale})"
        )
    lines.append("")
    lines.append("## Retrieved Historical Attack PoCs")
    lines.append("")
    attack_records = {record.id: record for record in memory.attack_poc_knowledge_base}
    if not memory.retrieved_attack_pocs:
        lines.append("No historical attack PoC records were retrieved.")
    for item in memory.retrieved_attack_pocs:
        record = attack_records.get(item.poc_id)
        if record is None:
            continue
        lines.append(
            f"- `{record.id}` ({record.source}, {record.category}): {record.title} "
            f"(score={item.score:.2f}; {item.rationale})"
        )
    lines.append("")
    lines.append("## Code Structure Map")
    lines.append("")
    lines.append(f"- Function call edges: {len(memory.call_edges)}")
    for edge in memory.call_edges[:20]:
        lines.append(f"  - `{edge.caller}` -> `{edge.callee}` ({edge.call_type}, confidence={edge.confidence:.2f})")
    lines.append(f"- Inheritance edges: {len(memory.inheritance_edges)}")
    for edge in memory.inheritance_edges[:20]:
        lines.append(f"  - `{edge.child}` inherits `{edge.parent}` at `{edge.path}:{edge.line_number}`")
    lines.append("")
    lines.append("## Business Flow Graph")
    lines.append("")
    if not memory.business_flows:
        lines.append("No business flow nodes were built.")
    for flow in memory.business_flows[:20]:
        lines.append(
            f"- `{flow.name}` ({flow.category}): state={', '.join(flow.state_variables) or 'N/A'}; "
            f"upstream={len(flow.upstream)}, downstream={len(flow.downstream)}"
        )
    lines.append("")
    lines.append("## Business Logic Units")
    lines.append("")
    if not memory.business_logic_units:
        lines.append("No business logic units were generated.")
    for unit in memory.business_logic_units[:20]:
        lines.append(f"- `{unit.name}`: {unit.summary}")
        for item in unit.risk_focus:
            lines.append(f"  - {item}")
    lines.append("")
    lines.append("## Business Audit Tasks")
    lines.append("")
    if not memory.audit_tasks:
        lines.append("No semantic-vulnerability audit tasks were generated.")
    for task in memory.audit_tasks[:20]:
        lines.append(
            f"- `{task.priority}` `{task.knowledge_id}` -> `{task.flow_id}`: "
            f"{task.vulnerability_pattern}"
        )
    lines.append("")
    lines.append("## Business Constraints")
    lines.append("")
    if not memory.business_constraints:
        lines.append("No business constraints were evaluated.")
    for constraint in memory.business_constraints[:30]:
        lines.append(
            f"- `{constraint.status}` `{constraint.severity_hint}` {constraint.title}: "
            f"{constraint.rationale}"
        )
        for item in constraint.evidence[:2]:
            lines.append(f"  - `{item}`")
    lines.append("")
    lines.append("## Top Hotspots")
    lines.append("")
    for hotspot in memory.hotspots[:10]:
        lines.append(
            f"- `{Path(hotspot.file_path).name}:{hotspot.name}` "
            f"(score={hotspot.score:.1f}, reads={len(hotspot.state_reads)}, writes={len(hotspot.state_writes)})"
        )
    lines.append("")
    lines.append("## Step 4 Vulnerability Validation")
    lines.append("")
    if not memory.validation_results:
        lines.append("No validation results were generated.")
    else:
        status_counts = Counter(result.status for result in memory.validation_results)
        lines.append("Status summary:")
        for status, count in sorted(status_counts.items()):
            lines.append(f"- `{status}`: {count}")
        lines.append("")
        for result in memory.validation_results:
            finding = findings_by_id.get(result.finding_id)
            title = finding.title if finding is not None else result.finding_id
            lines.append(f"### Validation: {title}")
            lines.append("")
            lines.append(f"- Status: `{result.status}`")
            lines.append(f"- Level: `{result.validation_level}`")
            lines.append(f"- Confidence: `{result.confidence:.2f}`")
            lines.append(f"- Rationale: {result.rationale}")
            lines.append("- Preconditions:")
            for item in result.preconditions:
                lines.append(f"  - {item}")
            lines.append("- False-positive checks:")
            for item in result.false_positive_checks:
                lines.append(f"  - {item}")
            lines.append("- Attack / validation path:")
            for item in result.attack_path:
                lines.append(f"  - {item}")
            lines.append("- Next validation steps:")
            for item in result.next_steps:
                lines.append(f"  - {item}")
            lines.append("")
    lines.append("## Root Cause And PoC Pipeline")
    lines.append("")
    if not memory.root_causes:
        lines.append("No root-cause records were generated.")
    for root_cause in memory.root_causes[:20]:
        lines.append(
            f"- `{root_cause.id}` ({root_cause.category}) for `{root_cause.finding_id}`: "
            f"{root_cause.root_cause}"
        )
        if root_cause.attack_poc_ids:
            lines.append(f"  - Historical PoCs: {', '.join(root_cause.attack_poc_ids)}")
    if memory.poc_drafts:
        lines.append("")
        lines.append("PoC drafts:")
        for draft in memory.poc_drafts[:20]:
            lines.append(
                f"- `{draft.id}` for `{draft.finding_id}`: {draft.status}; "
                f"targets={', '.join(draft.target_functions) or 'N/A'}"
            )
    if memory.foundry_results:
        lines.append("")
        lines.append("Foundry sandbox feedback:")
        for result in memory.foundry_results[:20]:
            lines.append(f"- `{result.draft_id}`: `{result.status}`; command=`{result.command}`")
            for item in result.feedback[:2]:
                lines.append(f"  - {item}")
    lines.append("")
    lines.append("## Security Patch Pipeline")
    lines.append("")
    if not memory.security_patches:
        lines.append("No security patch plans were generated.")
    for patch in memory.security_patches[:20]:
        lines.append(f"- `{patch.id}` for `{patch.finding_id}`: `{patch.validation_status}` - {patch.summary}")
        lines.append("  ```diff")
        for line in patch.diff.splitlines():
            lines.append(f"  {line}")
        lines.append("  ```")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not memory.findings:
        lines.append("No vulnerability findings were generated.")
    for index, finding in enumerate(memory.findings, start=1):
        lines.append(f"### {index}. {finding.title}")
        lines.append("")
        lines.append(f"- Severity: `{finding.severity}`")
        lines.append(f"- Confidence: `{finding.confidence:.2f}`")
        lines.append(f"- Tags: {', '.join(finding.tags) or 'N/A'}")
        lines.append(f"- Summary: {finding.summary}")
        lines.append(f"- Rationale: {finding.rationale}")
        validation = validations_by_finding.get(finding.id)
        if validation is not None:
            lines.append(
                f"- Validation: `{validation.status}` "
                f"/ `{validation.validation_level}` "
                f"(confidence={validation.confidence:.2f}) - {validation.rationale}"
            )
            if validation.attack_path:
                lines.append("- Validation path:")
                for item in validation.attack_path:
                    lines.append(f"  - {item}")
        lines.append("- Locations:")
        for location in finding.locations:
            lines.append(
                f"  - `{location.path}:{location.start_line}-{location.end_line}`"
            )
        lines.append("- Evidence:")
        for item in finding.evidence:
            lines.append(f"  - `{item}`")
        lines.append("- Suggested next steps:")
        for item in finding.remediation:
            lines.append(f"  - {item}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
