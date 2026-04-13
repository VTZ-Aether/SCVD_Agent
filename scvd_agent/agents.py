from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path

from .knowledge import (
    CURATED_AUDIT_KNOWLEDGE,
    ECONOMIC_KEYWORDS,
    SEVERITY_ORDER,
    STATE_SENSITIVE_VARIABLES,
    VALUATION_KEYWORDS,
    WORKFLOW_KEYWORDS,
    knowledge_by_id,
    retrieve_audit_knowledge,
)
from .models import (
    AuditTask,
    AuditKnowledgeRecord,
    BusinessConstraint,
    BusinessFlow,
    Finding,
    FunctionFact,
    ProjectProfile,
    SourceLocation,
    ValidationResult,
    WorkflowEdge,
    WorkingMemory,
)
from .parser import discover_document_chunks, parse_project


class ProjectProfilerAgent:
    def run(self, target_path: Path) -> WorkingMemory:
        source_files, state_vars_by_file, functions = parse_project(target_path)
        documents = discover_document_chunks(target_path)
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


class RAGKnowledgeAgent:
    def __init__(self, *, max_records: int = 6) -> None:
        self.max_records = max_records

    def run(self, memory: WorkingMemory) -> None:
        memory.knowledge_base = CURATED_AUDIT_KNOWLEDGE
        memory.retrieved_knowledge = retrieve_audit_knowledge(memory, limit=self.max_records)
        memory.notes.append(
            f"RAGKnowledgeAgent retrieved {len(memory.retrieved_knowledge)} audit knowledge records "
            "from the curated Code4rena/Sherlock-style knowledge base."
        )


class BusinessFlowGraphAgent:
    def run(self, memory: WorkingMemory) -> None:
        flows_by_function: dict[str, BusinessFlow] = {}
        writers_by_var: dict[str, list] = defaultdict(list)
        readers_by_var: dict[str, list] = defaultdict(list)

        for function in memory.functions:
            qualified = function.qualified_name
            keywords = sorted(function.economic_keywords | _function_name_tokens(function.name))
            state_variables = sorted(function.state_reads | function.state_writes)
            flow = BusinessFlow(
                id=_make_id(qualified, "business_flow"),
                name=function.name,
                category=_classify_flow(function),
                entry_points=[qualified],
                state_variables=state_variables,
                keywords=keywords,
            )
            flows_by_function[qualified] = flow
            for variable in function.state_writes:
                writers_by_var[variable].append(function)
            for variable in function.state_reads:
                readers_by_var[variable].append(function)

        for variable, writers in writers_by_var.items():
            for writer in writers:
                writer_flow = flows_by_function[writer.qualified_name]
                for reader in readers_by_var.get(variable, []):
                    if writer.qualified_name == reader.qualified_name:
                        continue
                    reader_flow = flows_by_function[reader.qualified_name]
                    if reader.qualified_name not in writer_flow.downstream:
                        writer_flow.downstream.append(reader.qualified_name)
                    if writer.qualified_name not in reader_flow.upstream:
                        reader_flow.upstream.append(writer.qualified_name)

        memory.business_flows = list(flows_by_function.values())
        memory.notes.append(
            f"BusinessFlowGraphAgent built {len(memory.business_flows)} function-level business flow nodes."
        )


class BusinessCompositionAgent:
    def run(self, memory: WorkingMemory) -> None:
        records = knowledge_by_id(memory.knowledge_base)
        retrieved_ids = [item.knowledge_id for item in memory.retrieved_knowledge]
        tasks: list[AuditTask] = []

        for flow in memory.business_flows:
            flow_terms = set(flow.keywords) | _terms_from_text(" ".join(flow.state_variables + [flow.category, flow.name]))
            for knowledge_id in retrieved_ids:
                record = records[knowledge_id]
                record_terms = _record_terms(record)
                overlap = flow_terms & record_terms
                if not overlap and flow.category != record.category:
                    continue
                pattern = record.vulnerability_patterns[0] if record.vulnerability_patterns else record.title
                semantic = record.semantics[0] if record.semantics else record.category
                tasks.append(
                    AuditTask(
                        id=_make_id(flow.id + knowledge_id, "audit_task"),
                        flow_id=flow.id,
                        knowledge_id=knowledge_id,
                        semantic=semantic,
                        vulnerability_pattern=pattern,
                        priority=record.severity_hint,
                        rationale=(
                            f"Flow `{flow.name}` ({flow.category}) overlaps retrieved knowledge "
                            f"`{record.title}` via {', '.join(sorted(overlap)[:6]) or 'category match'}."
                        ),
                    )
                )

        tasks.sort(key=lambda task: (SEVERITY_ORDER.get(task.priority, 0), task.knowledge_id), reverse=True)
        memory.audit_tasks = tasks[:40]
        memory.notes.append(
            f"BusinessCompositionAgent generated {len(memory.audit_tasks)} semantic-vulnerability audit tasks."
        )


class BusinessConstraintValidatorAgent:
    def run(self, memory: WorkingMemory) -> None:
        records = knowledge_by_id(memory.knowledge_base)
        flows = {flow.id: flow for flow in memory.business_flows}
        functions = {function.qualified_name: function for function in memory.functions}
        constraints: list[BusinessConstraint] = []

        for task in memory.audit_tasks:
            flow = flows.get(task.flow_id)
            record = records.get(task.knowledge_id)
            if flow is None or record is None:
                continue
            function = _flow_function(flow, functions)
            if function is None:
                continue
            status, rationale, evidence = _validate_record_against_function(record, function)
            if status == "not_applicable":
                continue
            constraints.append(
                BusinessConstraint(
                    id=_make_id(task.id + status, "constraint"),
                    title=record.title,
                    flow_id=flow.id,
                    knowledge_id=record.id,
                    invariant_type=record.category,
                    expression=record.constraints[0] if record.constraints else record.title,
                    severity_hint=record.severity_hint,
                    status=status,
                    rationale=rationale,
                    evidence=evidence,
                    related_functions=flow.entry_points,
                    locations=[function.location],
                )
            )

        memory.business_constraints = constraints
        memory.notes.append(
            f"BusinessConstraintValidatorAgent evaluated {len(constraints)} business constraints."
        )


class HotspotExtractionAgent:
    def run(self, memory: WorkingMemory) -> None:
        hotspots = []
        for function in memory.functions:
            if not function.arithmetic_sites:
                continue
            if function.economic_keywords or function.state_reads or function.state_writes:
                hotspots.append(function)
        hotspots.sort(key=lambda function: function.score, reverse=True)
        memory.hotspots = hotspots
        memory.notes.append(
            f"HotspotExtractionAgent selected {len(hotspots)} arithmetic hotspots with economic relevance."
        )


class WorkflowMapperAgent:
    def run(self, memory: WorkingMemory) -> None:
        writers_by_var: dict[str, list] = defaultdict(list)
        readers_by_var: dict[str, list] = defaultdict(list)

        for function in memory.hotspots:
            for variable in function.state_writes:
                writers_by_var[variable].append(function)
            for variable in function.state_reads:
                readers_by_var[variable].append(function)

        edges: list[WorkflowEdge] = []
        for variable, writers in writers_by_var.items():
            if not any(hint in variable.lower() for hint in STATE_SENSITIVE_VARIABLES):
                continue
            readers = readers_by_var.get(variable, [])
            for writer in writers:
                for reader in readers:
                    if writer.qualified_name == reader.qualified_name:
                        continue
                    if (writer.has_floor_rounding or writer.risky_markers) and (
                        reader.branch_markers
                        or reader.economic_keywords & VALUATION_KEYWORDS
                    ):
                        edges.append(
                            WorkflowEdge(
                                variable=variable,
                                writer=writer.qualified_name,
                                reader=reader.qualified_name,
                                rationale=(
                                    f"{variable} is updated with arithmetic in {writer.name} and later drives "
                                    f"valuation/branching logic in {reader.name}."
                                ),
                            )
                        )

        memory.workflow_edges = edges
        memory.notes.append(
            f"WorkflowMapperAgent built {len(edges)} candidate arithmetic drift edges across functions."
        )


class HypothesisAgent:
    def run(self, memory: WorkingMemory) -> None:
        findings: list[Finding] = []
        for function in memory.hotspots:
            findings.extend(self._function_findings(function))
        findings.extend(self._workflow_findings(memory))
        memory.findings = findings
        memory.notes.append(
            f"HypothesisAgent generated {len(findings)} raw arithmetic hypotheses."
        )

    def _function_findings(self, function) -> list[Finding]:
        findings: list[Finding] = []
        lower_source = function.source.lower()

        if (
            function.has_division
            and function.economic_keywords
            and function.economic_keywords & WORKFLOW_KEYWORDS
            and function.state_writes
            and any(keyword in lower_source for keyword in {"share", "liquidity", "reserve", "balance", "supply"})
            and not function.has_explicit_rounding_control
        ):
            findings.append(
                self._make_finding(
                    function=function,
                    suffix="rounding_drift",
                    title="Implicit floor rounding in an economic conversion path",
                    severity="medium",
                    confidence=0.62,
                    summary=(
                        "This function performs integer division in a value-conversion path "
                        "without an explicit rounding policy."
                    ),
                    rationale=(
                        "Repeated calls to deposit/withdraw/mint/burn style functions can accumulate "
                        "truncation error and bias economic outcomes."
                    ),
                    tags=["arithmetic", "rounding", "economic_conversion"],
                    remediation=[
                        "Document the intended rounding direction.",
                        "Add differential tests against a high-precision reference model.",
                        "Check whether repeated small interactions accumulate value drift.",
                    ],
                )
            )

        if function.has_division and _uses_state_denominator(function) and not _has_relevant_zero_guard(function):
            findings.append(
                self._make_finding(
                    function=function,
                    suffix="boundary_state",
                    title="Arithmetic over stateful denominator without a clear boundary-state guard",
                    severity="high",
                    confidence=0.68,
                    summary=(
                        "This function divides by a state-sensitive denominator but does not "
                        "show a nearby zero or bootstrap guard."
                    ),
                    rationale=(
                        "Arithmetic defects often become exploitable in low-liquidity, zero-supply, or "
                        "bootstrap states where denominators shrink and truncation dominates."
                    ),
                    tags=["arithmetic", "boundary_state", "bootstrap"],
                    remediation=[
                        "Explicitly handle zero-supply and low-liquidity states.",
                        "Add regression tests for bootstrap and near-empty states.",
                    ],
                )
            )

        if (
            function.has_division
            and function.economic_keywords & WORKFLOW_KEYWORDS
            and function.state_writes
            and not function.has_explicit_rounding_control
            and any(keyword in lower_source for keyword in {"withdraw", "redeem", "remove", "burn", "swap", "deposit", "mint"})
            and any(keyword in lower_source for keyword in {"balance", "reserve", "liquidity", "supply"})
        ):
            findings.append(
                self._make_finding(
                    function=function,
                    suffix="repeated_interaction",
                    title="Proportional arithmetic update may amplify drift under repeated interactions",
                    severity="medium",
                    confidence=0.58,
                    summary=(
                        "The function proportionally updates economic state using integer arithmetic, "
                        "which can accumulate drift across many small calls."
                    ),
                    rationale=(
                        "This is the typical precondition for repeated tiny interaction attacks, where each "
                        "call leaks only a tiny amount but the sequence becomes exploitable."
                    ),
                    tags=["arithmetic", "repeated_interaction", "workflow"],
                    remediation=[
                        "Stress-test repeated tiny deposits/withdrawals against a reference model.",
                        "Track value drift over long sequences instead of only checking per-call correctness.",
                    ],
                )
            )

        if function.risky_markers and function.economic_keywords:
            findings.append(
                self._make_finding(
                    function=function,
                    suffix="unsafe_math",
                    title="Unchecked or unsafe arithmetic inside an economic workflow",
                    severity="high",
                    confidence=0.78,
                    summary=(
                        "Unchecked or explicitly unsafe arithmetic appears in a value-sensitive function."
                    ),
                    rationale=(
                        "Even when overflow is not the direct issue, unsafe arithmetic obscures whether "
                        "the workflow preserves intended economic invariants."
                    ),
                    tags=["arithmetic", "unsafe_math", "economic_workflow"],
                    remediation=[
                        "Replace unsafe arithmetic with checked or library-backed arithmetic.",
                        "Add invariant tests around share value, reserve conservation, and user redemption.",
                    ],
                )
            )

        if (
            function.economic_keywords
            and any(keyword in lower_source for keyword in {"rate", "price", "index", "decimal", "scale"})
            and function.has_division
            and not function.precision_markers
        ):
            findings.append(
                self._make_finding(
                    function=function,
                    suffix="scaling",
                    title="Potential scaling or precision mismatch in economic arithmetic",
                    severity="medium",
                    confidence=0.54,
                    summary=(
                        "The function mixes rate/index/price-like values with division but lacks visible "
                        "precision constants or explicit scaling discipline."
                    ),
                    rationale=(
                        "Cross-token conversion, rate application, and index updates are a common source "
                        "of silent value drift."
                    ),
                    tags=["arithmetic", "scaling", "precision"],
                    remediation=[
                        "Normalize unit conversions and scale markers in the arithmetic path.",
                        "Add assertions for monotonicity and redemption equivalence after conversions.",
                    ],
                )
            )

        return findings

    def _workflow_findings(self, memory: WorkingMemory) -> list[Finding]:
        findings: list[Finding] = []
        function_map = {function.qualified_name: function for function in memory.hotspots}
        grouped_edges: dict[tuple[str, str], list[WorkflowEdge]] = defaultdict(list)
        for edge in memory.workflow_edges:
            grouped_edges[(edge.writer, edge.reader)].append(edge)

        for (writer_name, reader_name), edges in grouped_edges.items():
            writer = function_map[writer_name]
            reader = function_map[reader_name]
            locations = [writer.location, reader.location]
            evidence = [edge.rationale for edge in edges]
            evidence.extend(_top_evidence_lines(writer, limit=2))
            evidence.extend(_top_evidence_lines(reader, limit=2))
            findings.append(
                Finding(
                    id=_make_id(writer_name + reader_name, "workflow_drift"),
                    title="Workflow-level arithmetic drift can propagate into valuation logic",
                    severity="high",
                    confidence=min(0.9, 0.72 + 0.03 * len(edges)),
                    summary=(
                        f"{writer.name} updates {', '.join(sorted({edge.variable for edge in edges}))} with arithmetic, "
                        f"and {reader.name} later uses the same state in valuation or branch-selection logic."
                    ),
                    rationale=(
                        "This pattern is consistent with transaction-semantic arithmetic defects where local "
                        "rounding or truncation becomes globally exploitable only after a later estimate, quote, "
                        "or regime switch."
                    ),
                    evidence=evidence,
                    locations=locations,
                    tags=["arithmetic", "workflow", "misvaluation", "cross_function"],
                    related_functions=[writer_name, reader_name],
                    remediation=[
                        "Replay the two-function workflow with a high-precision shadow model.",
                        "Stress boundary states and repeated small interactions before the valuation path.",
                    ],
                )
            )
        return findings

    def _make_finding(
        self,
        *,
        function,
        suffix: str,
        title: str,
        severity: str,
        confidence: float,
        summary: str,
        rationale: str,
        tags: list[str],
        remediation: list[str],
    ) -> Finding:
        return Finding(
            id=_make_id(function.qualified_name, suffix),
            title=title,
            severity=severity,
            confidence=confidence,
            summary=summary,
            rationale=rationale,
            evidence=_top_evidence_lines(function, limit=3),
            locations=[function.location],
            tags=tags,
            related_functions=[function.qualified_name],
            remediation=remediation,
        )


class VulnerabilityReasoningAgent:
    def run(self, memory: WorkingMemory) -> None:
        records = knowledge_by_id(memory.knowledge_base)
        existing_ids = {finding.id for finding in memory.findings}
        generated: list[Finding] = []

        for constraint in memory.business_constraints:
            if constraint.status != "violated":
                continue
            record = records.get(constraint.knowledge_id)
            if record is None:
                continue
            finding_id = _make_id(constraint.id, "business_reasoning")
            if finding_id in existing_ids:
                continue
            generated.append(
                Finding(
                    id=finding_id,
                    title=f"Business constraint violation: {constraint.title}",
                    severity=constraint.severity_hint,
                    confidence=_constraint_confidence(constraint),
                    summary=constraint.expression,
                    rationale=constraint.rationale,
                    evidence=list(dict.fromkeys(constraint.evidence + [constraint.expression])),
                    locations=constraint.locations,
                    tags=["business_constraint", "rag", record.category],
                    related_functions=constraint.related_functions,
                    remediation=record.remediation,
                )
            )

        memory.findings.extend(generated)
        memory.notes.append(
            f"VulnerabilityReasoningAgent promoted {len(generated)} violated business constraints to findings."
        )


class ValidationAgent:
    def run(self, memory: WorkingMemory) -> None:
        results: list[ValidationResult] = []
        already_validated = {result.finding_id for result in memory.validation_results}

        for finding in memory.findings:
            has_locations = bool(finding.locations)
            has_evidence = bool(finding.evidence)
            preconditions = _validation_preconditions(finding)
            false_positive_checks = _validation_false_positive_checks(finding)
            attack_path = _validation_attack_path(finding)
            next_steps = _validation_next_steps(finding)
            if "business_constraint" in finding.tags and has_locations and has_evidence:
                status = "static_validated"
                validation_level = "static_constraint_check"
                delta = 0.0 if finding.id in already_validated else _validation_confidence_delta(finding, 0.06)
                confidence = min(0.95, finding.confidence + delta)
                rationale = (
                    "Finding is backed by a retrieved audit knowledge constraint, concrete code evidence, "
                    "and a generated false-positive checklist."
                )
            elif has_locations and has_evidence:
                status = "needs_dynamic_validation"
                validation_level = "dynamic_required"
                delta = 0.0 if finding.id in already_validated else _validation_confidence_delta(finding, 0.02)
                confidence = min(0.9, finding.confidence + delta)
                rationale = (
                    "Finding has static evidence and a candidate attack path, but still needs sequence, fuzz, "
                    "or fork validation before it should be treated as confirmed."
                )
            else:
                status = "insufficient_evidence"
                validation_level = "insufficient_static_evidence"
                confidence = max(0.0, finding.confidence - 0.2)
                rationale = "Finding lacks enough static evidence for validation."
                next_steps = ["Collect concrete source evidence before attempting dynamic validation."]

            finding.confidence = confidence
            results.append(
                ValidationResult(
                    finding_id=finding.id,
                    status=status,
                    confidence=confidence,
                    rationale=rationale,
                    validation_level=validation_level,
                    preconditions=preconditions,
                    false_positive_checks=false_positive_checks,
                    attack_path=attack_path,
                    next_steps=next_steps,
                    evidence=finding.evidence[:4],
                )
            )

        memory.validation_results = results
        memory.notes.append(
            f"ValidationAgent produced {len(results)} detailed validation results with preconditions, "
            "false-positive checks, and attack paths."
        )


class ReflectionAgent:
    def run(self, memory: WorkingMemory) -> None:
        deduped: dict[tuple[str, tuple[str, ...]], Finding] = {}
        for finding in memory.findings:
            key = (
                finding.title,
                tuple(sorted(location.path + f":{location.start_line}" for location in finding.locations)),
            )
            existing = deduped.get(key)
            if existing is None:
                deduped[key] = finding
                continue

            existing.confidence = max(existing.confidence, finding.confidence)
            if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[existing.severity]:
                existing.severity = finding.severity
            existing.evidence = list(dict.fromkeys(existing.evidence + finding.evidence))
            existing.tags = sorted(set(existing.tags + finding.tags))
            existing.related_functions = sorted(set(existing.related_functions + finding.related_functions))

        findings = list(deduped.values())
        findings.sort(key=lambda item: (SEVERITY_ORDER[item.severity], item.confidence), reverse=True)
        memory.findings = findings
        memory.notes.append(
            f"ReflectionAgent reduced the report to {len(findings)} consolidated findings."
        )


def _make_id(seed: str, suffix: str) -> str:
    digest = hashlib.sha1(f"{seed}:{suffix}".encode("utf-8")).hexdigest()[:10]
    return f"{suffix}-{digest}"


def _function_name_tokens(name: str) -> set[str]:
    return _terms_from_text(name)


def _classify_flow(function: FunctionFact) -> str:
    lower_source = function.source.lower()
    terms = _function_name_tokens(function.name) | function.economic_keywords
    if {"deposit", "mint", "stake"} & terms:
        return "deposit"
    if {"withdraw", "redeem", "burn", "unstake"} & terms:
        return "withdraw"
    if "swap" in terms:
        return "swap"
    if {"quote", "preview", "price", "value", "oracle", "convert"} & terms:
        return "valuation"
    if {"reward", "claim", "harvest"} & terms:
        return "reward"
    if {"transfer", "send", "payment"} & terms:
        return "transfer"
    if (
        function.name.lower().startswith(("set", "pause", "unpause", "upgrade", "initialize"))
        or {"owner", "admin", "role"} & terms
        or any(marker in lower_source for marker in ("onlyowner", "onlyrole", "upgrade", "delegatecall"))
    ):
        return "admin"
    if function.state_writes:
        return "state-mutation"
    return "read-only"


def _record_terms(record: AuditKnowledgeRecord) -> set[str]:
    joined = " ".join(
        [
            record.title,
            record.category,
            " ".join(record.semantics),
            " ".join(record.vulnerability_patterns),
            " ".join(record.detection_cues),
            " ".join(record.constraints),
        ]
    )
    return _terms_from_text(joined)


def _terms_from_text(text: str) -> set[str]:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return {
        token.lower()
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", normalized)
        if len(token) > 2
    }


def _flow_function(flow: BusinessFlow, functions: dict[str, FunctionFact]) -> FunctionFact | None:
    for entry_point in flow.entry_points:
        function = functions.get(entry_point)
        if function is not None:
            return function
    return None


def _validate_record_against_function(
    record: AuditKnowledgeRecord,
    function: FunctionFact,
) -> tuple[str, str, list[str]]:
    category = record.category
    lower_source = function.source.lower()
    evidence = _function_context_lines(function, limit=4)

    if category == "accounting":
        if function.has_division and _uses_state_denominator(function):
            if _has_relevant_zero_guard(function) and function.has_explicit_rounding_control:
                return (
                    "satisfied",
                    f"`{function.qualified_name}` handles state denominators with visible guards and rounding policy.",
                    evidence,
                )
            if not _has_relevant_zero_guard(function):
                return (
                    "violated",
                    f"`{function.qualified_name}` divides by state-sensitive accounting data without a visible bootstrap or zero-state guard.",
                    evidence,
                )
            return (
                "needs_review",
                f"`{function.qualified_name}` has a denominator guard, but the rounding or first-depositor policy is not explicit.",
                evidence,
            )
        return ("not_applicable", "", [])

    if category == "arithmetic":
        if function.has_division and function.has_floor_rounding and not function.has_explicit_rounding_control:
            if function.precision_markers and not _has_division_before_multiplication(function):
                return (
                    "satisfied",
                    f"`{function.qualified_name}` uses precision markers and does not show a simple division-before-multiplication pattern.",
                    evidence,
                )
            return (
                "violated",
                f"`{function.qualified_name}` contains floor-like division in an economic path without explicit rounding control.",
                evidence,
            )
        return ("not_applicable", "", [])

    if category == "oracle":
        spot_oracle = any(marker in lower_source for marker in ("getreserves", "slot0", "balanceof", "spot"))
        valuation_path = function.economic_keywords & VALUATION_KEYWORDS or any(
            marker in lower_source for marker in ("price", "quote", "oracle", "liquidate", "borrow")
        )
        freshness_guard = any(marker in lower_source for marker in ("updatedat", "heartbeat", "answeredinround", "twap"))
        if spot_oracle and valuation_path and not freshness_guard:
            return (
                "violated",
                f"`{function.qualified_name}` appears to trust a spot or balance-derived price in a valuation path.",
                evidence,
            )
        if valuation_path and freshness_guard:
            return (
                "satisfied",
                f"`{function.qualified_name}` includes freshness/TWAP-style oracle checks in a valuation path.",
                evidence,
            )
        return ("not_applicable", "", [])

    if category == "access-control":
        privileged = _looks_privileged(function)
        if not privileged:
            return ("not_applicable", "", [])
        if _has_access_guard(function):
            return (
                "satisfied",
                f"`{function.qualified_name}` mutates privileged state and has a visible caller restriction.",
                evidence,
            )
        return (
            "violated",
            f"`{function.qualified_name}` looks like a privileged mutation but lacks an onlyOwner/onlyRole/msg.sender guard.",
            evidence,
        )

    if category == "reentrancy":
        external_call = _has_external_call(function)
        if not external_call:
            return ("not_applicable", "", [])
        if "nonreentrant" in lower_source:
            return (
                "satisfied",
                f"`{function.qualified_name}` performs external interactions with a visible nonReentrant guard.",
                evidence,
            )
        if function.state_writes and _external_call_before_state_write(function):
            return (
                "violated",
                f"`{function.qualified_name}` performs an external interaction before completing state updates.",
                evidence,
            )
        if function.state_writes:
            return (
                "needs_review",
                f"`{function.qualified_name}` mixes external interactions and shared state updates; CEI ordering needs manual confirmation.",
                evidence,
            )
        return ("not_applicable", "", [])

    if category == "external-call":
        token_call = any(marker in lower_source for marker in ("transferfrom", ".transfer(", ".approve("))
        if not token_call:
            return ("not_applicable", "", [])
        safe_wrapper = any(marker in lower_source for marker in ("safeerc20", "safetransfer", "safetransferfrom"))
        balance_delta = "balancebefore" in lower_source and "balanceafter" in lower_source
        if safe_wrapper or balance_delta:
            return (
                "satisfied",
                f"`{function.qualified_name}` uses safe token wrappers or balance-delta accounting.",
                evidence,
            )
        return (
            "violated",
            f"`{function.qualified_name}` calls ERC20 transfer/transferFrom without a visible safe wrapper or balance-delta check.",
            evidence,
        )

    if category == "signature":
        signature_path = any(marker in lower_source for marker in ("ecrecover", "ecdsa", "domain_separator", "permit"))
        if not signature_path:
            return ("not_applicable", "", [])
        has_nonce = any(marker in lower_source for marker in ("nonce", "nonces"))
        has_domain = any(marker in lower_source for marker in ("chainid", "address(this)", "domain_separator"))
        has_deadline = "deadline" in lower_source or "expiry" in lower_source
        if has_nonce and has_domain and has_deadline:
            return (
                "satisfied",
                f"`{function.qualified_name}` includes nonce, domain, and expiration checks for signatures.",
                evidence,
            )
        return (
            "violated",
            f"`{function.qualified_name}` verifies signatures without all nonce/domain/deadline protections visible.",
            evidence,
        )

    if category == "dos":
        if function.loop_count <= 0:
            return ("not_applicable", "", [])
        if _has_external_call(function):
            return (
                "violated",
                f"`{function.qualified_name}` loops while performing push-style external interactions.",
                evidence,
            )
        return (
            "needs_review",
            f"`{function.qualified_name}` contains loops that may be unsafe if they iterate over user-growing storage.",
            evidence,
        )

    if category == "upgradeability":
        upgrade_path = any(marker in lower_source for marker in ("initializer", "reinitializer", "upgradeto", "delegatecall", "__gap"))
        if not upgrade_path:
            return ("not_applicable", "", [])
        if _has_access_guard(function) or "_disableinitializers" in lower_source:
            return (
                "satisfied",
                f"`{function.qualified_name}` has visible upgrade/initializer authorization or initializer disabling.",
                evidence,
            )
        return (
            "needs_review",
            f"`{function.qualified_name}` touches upgradeability markers without visible authorization in the local function body.",
            evidence,
        )

    return ("not_applicable", "", [])


def _constraint_confidence(constraint: BusinessConstraint) -> float:
    severity_boost = {
        "critical": 0.82,
        "high": 0.78,
        "medium": 0.68,
        "low": 0.58,
    }
    return severity_boost.get(constraint.severity_hint, 0.6)


def _validation_preconditions(finding: Finding) -> list[str]:
    tags = set(finding.tags)
    text = _finding_text(finding)
    preconditions: list[str] = []

    if tags & {"accounting", "bootstrap", "boundary_state"} or "first-depositor" in text:
        preconditions.extend(
            [
                "State-sensitive denominator can enter zero, near-zero, or bootstrap state.",
                "The affected flow changes user-visible assets, shares, supply, reserves, or liquidity.",
            ]
        )
    if tags & {"arithmetic", "rounding", "precision"}:
        preconditions.extend(
            [
                "Integer arithmetic result can differ from a high-precision reference model.",
                "Rounding direction is economically observable by a caller or downstream valuation path.",
            ]
        )
    if "workflow" in tags or "cross_function" in tags:
        preconditions.append("A writer flow mutates state that is later read by a valuation or branch-selection flow.")
    if "oracle" in tags:
        preconditions.append("The trusted price source can be moved or made stale inside the attack window.")
    if "access-control" in tags:
        preconditions.append("A non-privileged account can reach the state-changing entry point.")
    if "reentrancy" in tags:
        preconditions.append("An external call can trigger attacker-controlled callback code before accounting is closed.")
    if "external-call" in tags:
        preconditions.append("The integrated token or external contract can behave non-standardly.")
    if "signature" in tags:
        preconditions.append("A captured signature can be submitted again across nonce, contract, or chain domains.")
    if "dos" in tags:
        preconditions.append("A user-controlled collection or recipient set can grow enough to affect liveness.")
    if "upgradeability" in tags:
        preconditions.append("Initializer or upgrade entry points are reachable after deployment.")

    if not preconditions:
        preconditions.append("The finding has a concrete source location and code evidence.")
    return list(dict.fromkeys(preconditions))


def _validation_false_positive_checks(finding: Finding) -> list[str]:
    tags = set(finding.tags)
    text = _finding_text(finding)
    checks: list[str] = []

    if tags & {"accounting", "bootstrap", "boundary_state"}:
        checks.extend(
            [
                "Check for explicit zero-supply, virtual-liquidity, or minimum-liquidity bootstrap handling.",
                "Check whether the denominator is provably non-zero before the function is callable.",
            ]
        )
    if tags & {"arithmetic", "rounding", "precision"}:
        checks.extend(
            [
                "Check for explicit ceil/floor rounding policy or mulDiv helper with documented direction.",
                "Check whether truncation is intentionally bounded and tested for tiny amounts.",
            ]
        )
    if "workflow" in tags or "cross_function" in tags:
        checks.append("Check whether downstream valuation reads a refreshed value rather than the mutated stale state.")
    if "oracle" in tags:
        checks.append("Check for TWAP, Chainlink freshness/deviation checks, or a non-manipulable oracle source.")
    if "access-control" in tags:
        checks.append("Check modifiers and inherited role checks not visible in the local function body.")
    if "reentrancy" in tags:
        checks.append("Check for nonReentrant guards and checks-effects-interactions ordering across all shared-state entry points.")
    if "external-call" in tags:
        checks.append("Check for SafeERC20 wrappers, low-level return handling, or balance-delta accounting.")
    if "signature" in tags:
        checks.append("Check for nonce consumption, deadline checks, chain id, verifying contract, and signer malleability guards.")
    if "dos" in tags:
        checks.append("Check whether loop bounds are admin-capped, paginated, or pull-payment based.")
    if "upgradeability" in tags:
        checks.append("Check deployment scripts, inherited upgrade authorization, and storage layout reports.")
    if "static_validated" in text:
        checks.append("Check whether the static validation result was superseded by a later LLM or dynamic run.")

    if not checks:
        checks.append("Check whether the evidence snippet is a syntactic match without an exploitable state transition.")
    return list(dict.fromkeys(checks))


def _validation_attack_path(finding: Finding) -> list[str]:
    tags = set(finding.tags)
    functions = [_short_function_name(name) for name in finding.related_functions]
    subject = ", ".join(functions) or "the affected entry point"

    if tags & {"accounting", "bootstrap", "boundary_state"}:
        return [
            f"Move protocol state into a zero or near-zero denominator condition around {subject}.",
            "Execute the affected conversion with a tiny or first-depositor-sized amount.",
            "Compare credited assets/shares/liquidity against a high-precision shadow model.",
            "Repeat or follow with the downstream valuation path to measure value drift.",
        ]
    if "workflow" in tags or "cross_function" in tags:
        return [
            f"Call the writer flow in {subject} with boundary-sized input.",
            "Record changed state variables and expected high-precision values.",
            "Call the downstream valuation or branch-selection flow in the same scenario.",
            "Assert that observed output matches the shadow model across repeated interactions.",
        ]
    if tags & {"arithmetic", "rounding", "precision"}:
        return [
            f"Generate tiny, boundary, and mixed-decimal inputs for {subject}.",
            "Evaluate the formula with both contract arithmetic and a high-precision reference.",
            "Search for repeated-call sequences where the delta compounds.",
        ]
    if "oracle" in tags:
        return [
            "Manipulate the referenced spot reserve or balance inside a single transaction.",
            f"Call {subject} while the manipulated price is active.",
            "Check whether the protocol mints, borrows, redeems, or liquidates at the manipulated value.",
        ]
    if "access-control" in tags:
        return [
            f"Call {subject} from a non-owner/non-role account.",
            "Assert whether privileged state changes or value movements succeed.",
        ]
    if "reentrancy" in tags:
        return [
            "Use an attacker contract/token receiver that re-enters during the external interaction.",
            f"Trigger {subject} and re-enter a related shared-state entry point.",
            "Assert whether stale accounting can be observed or mutated twice.",
        ]
    if "external-call" in tags:
        return [
            "Replace the token/external dependency with a no-return, fee-on-transfer, rebasing, or reverting mock.",
            f"Execute {subject} and compare credited accounting against actual balance deltas.",
        ]
    if "signature" in tags:
        return [
            "Submit a valid signed authorization once.",
            "Replay the same signature across the same contract, another contract, or another chain domain.",
            "Assert that nonce/domain/deadline protections reject every replay.",
        ]
    if "dos" in tags:
        return [
            "Grow the recipient or storage collection to a worst-case size.",
            f"Execute {subject} and measure gas, revert behavior, and per-recipient failure handling.",
        ]
    if "upgradeability" in tags:
        return [
            "Attempt initializer or upgrade calls from unauthorized accounts and after initialization.",
            "Compare storage layout before and after the candidate upgrade path.",
        ]
    return [f"Replay {subject} with the source evidence conditions and assert the expected invariant."]


def _validation_next_steps(finding: Finding) -> list[str]:
    tags = set(finding.tags)
    steps: list[str] = []

    if tags & {"accounting", "arithmetic", "bootstrap", "boundary_state", "workflow", "cross_function"}:
        steps.extend(
            [
                "Build a high-precision reference model for the affected flow.",
                "Add Foundry/Medusa stateful tests for boundary states and repeated interactions.",
            ]
        )
    if "oracle" in tags:
        steps.append("Add a flash-loan or reserve-manipulation fork test around the valuation path.")
    if "access-control" in tags:
        steps.append("Add negative authorization tests for every role tier.")
    if "reentrancy" in tags:
        steps.append("Add callback-based reentrancy tests covering all shared-state entry points.")
    if "external-call" in tags:
        steps.append("Run the flow against weird ERC20 mocks: no-return, fee-on-transfer, rebasing, blacklist, and callback tokens.")
    if "signature" in tags:
        steps.append("Add replay tests for same-chain, cross-chain, cross-contract, expired, and nonce-reuse cases.")
    if "dos" in tags:
        steps.append("Add gas-bound and revert-isolation tests for large recipient sets.")
    if "upgradeability" in tags:
        steps.append("Run storage layout checks and initializer authorization tests.")
    if not steps:
        steps.append("Convert the static candidate into a minimal regression test before reporting as confirmed.")
    return list(dict.fromkeys(steps))


def _validation_confidence_delta(finding: Finding, base_delta: float) -> float:
    evidence_weight = 0.01 * min(len(finding.evidence), 4)
    severity_weight = {"critical": 0.02, "high": 0.015, "medium": 0.005}.get(finding.severity, 0.0)
    heuristic_penalty = -0.02 if not finding.locations else 0.0
    return base_delta + evidence_weight + severity_weight + heuristic_penalty


def _finding_text(finding: Finding) -> str:
    return " ".join(
        [
            finding.title,
            finding.summary,
            finding.rationale,
            " ".join(finding.tags),
            " ".join(finding.evidence),
        ]
    ).lower()


def _short_function_name(qualified_name: str) -> str:
    return qualified_name.rsplit(":", 1)[-1]


def _has_division_before_multiplication(function: FunctionFact) -> bool:
    for site in function.arithmetic_sites:
        code = site.code
        if "/" in code and "*" in code and code.index("/") < code.rindex("*"):
            return True
    return False


def _looks_privileged(function: FunctionFact) -> bool:
    lower_name = function.name.lower()
    lower_source = function.source.lower()
    if lower_name.startswith(("set", "pause", "unpause", "upgrade", "initialize")):
        return bool(function.state_writes or "delegatecall" in lower_source)
    if any(marker in lower_source for marker in ("owner", "admin", "role", "mint", "_mint", "burn", "_burn")):
        return bool(function.state_writes)
    return False


def _has_access_guard(function: FunctionFact) -> bool:
    lower_source = function.source.lower()
    return any(
        marker in lower_source
        for marker in ("onlyowner", "onlyrole", "onlyadmin", "msg.sender", "_checkrole", "hasrole")
    )


def _has_external_call(function: FunctionFact) -> bool:
    lower_source = function.source.lower()
    return any(
        marker in lower_source
        for marker in (
            ".call(",
            ".call{",
            ".delegatecall(",
            ".staticcall(",
            ".send(",
            ".transfer(",
            "safetransfer",
            "safemint",
            "transferfrom",
        )
    )


def _external_call_before_state_write(function: FunctionFact) -> bool:
    state_write_lines: list[int] = []
    external_call_lines: list[int] = []
    state_vars = function.state_writes
    for offset, line in enumerate(function.source.splitlines(), start=function.start_line):
        lower_line = line.lower()
        if any(
            marker in lower_line
            for marker in (".call(", ".call{", ".send(", ".transfer(", "safetransfer", "safemint", "transferfrom")
        ):
            external_call_lines.append(offset)
        if any(re.search(rf"\b{re.escape(variable)}\b\s*(?:\[[^\]]+\])?\s*[-+*/%]?=", line) for variable in state_vars):
            state_write_lines.append(offset)
    return bool(external_call_lines and state_write_lines and min(external_call_lines) < max(state_write_lines))


def _function_context_lines(function: FunctionFact, *, limit: int) -> list[str]:
    lines: list[str] = []
    lines.extend(_top_evidence_lines(function, limit=limit))
    if len(lines) >= limit:
        return lines[:limit]

    markers = [
        "require",
        "assert",
        "if",
        "call",
        "transfer",
        "transferFrom",
        "safeTransfer",
        "ecrecover",
        "getReserves",
        "slot0",
        "balanceOf",
    ]
    for offset, raw_line in enumerate(function.source.splitlines(), start=function.start_line):
        stripped = raw_line.strip()
        lower_line = stripped.lower()
        if not stripped or not any(marker.lower() in lower_line for marker in markers):
            continue
        item = f"{function.file_path}:{offset}: {stripped}"
        if item not in lines:
            lines.append(item)
        if len(lines) >= limit:
            break
    if lines:
        return lines[:limit]
    return [f"{function.file_path}:{function.start_line}: {function.name}"]


def _top_evidence_lines(function, *, limit: int) -> list[str]:
    return [
        f"{function.file_path}:{site.line_number}: {site.code}"
        for site in function.arithmetic_sites[:limit]
    ]


def _uses_state_denominator(function) -> bool:
    for site in function.arithmetic_sites:
        line = site.code.lower()
        if "division" not in site.tags:
            continue
        denominator = line.split("/", 1)[1] if "/" in line else line
        if any(
            keyword in denominator
            for keyword in {
                "supply",
                "reserve",
                "balance",
                "liquidity",
                "assets",
                "shares",
                "density",
                "rate",
                "index",
                "price",
                "amount",
            }
        ):
            return True
    return False


def _has_relevant_zero_guard(function) -> bool:
    return bool(
        function.guards
        & {
            variable
            for variable in function.state_reads | function.state_writes
            if any(
                keyword in variable.lower()
                for keyword in {
                    "supply",
                    "reserve",
                    "balance",
                    "liquidity",
                    "asset",
                    "share",
                    "density",
                    "rate",
                    "index",
                    "price",
                    "amount",
                }
            )
        }
    )
