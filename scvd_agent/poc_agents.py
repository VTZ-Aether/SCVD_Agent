from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from .models import FoundryRunResult, PocDraft, RootCauseAnalysis, WorkingMemory
from .rag_agents import attack_poc_by_id


class PocPlanningAgent:
    """LLM4 role: turn root cause + historical PoC knowledge into initial PoC drafts."""

    def run(self, memory: WorkingMemory) -> None:
        findings = {finding.id: finding for finding in memory.findings}
        attack_records = attack_poc_by_id(memory.attack_poc_knowledge_base)
        drafts: list[PocDraft] = []

        for root_cause in memory.root_causes:
            finding = findings.get(root_cause.finding_id)
            if finding is None:
                continue
            selected_poc = attack_records.get(root_cause.attack_poc_ids[0]) if root_cause.attack_poc_ids else None
            draft = PocDraft(
                id=_make_id(root_cause.id, "poc_draft"),
                finding_id=finding.id,
                root_cause_id=root_cause.id,
                title=f"Initial PoC plan for {finding.title}",
                target_functions=list(finding.related_functions),
                fork_block=selected_poc.default_fork_block if selected_poc else None,
                code=_poc_code_template(root_cause, selected_poc.code_template if selected_poc else ""),
                status="initial_poc",
                feedback=[],
                next_steps=[
                    "Place the draft under test/ and replace placeholders with deployed contract setup.",
                    "Add concrete attacker/victim balances and boundary-state initialization.",
                    "Run forge test with a fork block when the target depends on mainnet state.",
                ],
            )
            drafts.append(draft)

        memory.poc_drafts = drafts
        memory.notes.append(f"PocPlanningAgent drafted {len(drafts)} initial PoC plans.")


class FoundrySandboxAgent:
    """Foundry sandbox module: compile/run feedback abstraction for generated PoC plans."""

    def run(self, memory: WorkingMemory) -> None:
        root = Path(memory.profile.root)
        has_foundry_project = (root / "foundry.toml").exists()
        forge_path = shutil.which("forge")
        results: list[FoundryRunResult] = []

        for draft in memory.poc_drafts:
            command = _forge_command(draft)
            if not has_foundry_project:
                status = "not_run"
                feedback = ["No foundry.toml was found; sandbox run is represented as a Foundry migration plan."]
                compiled = False
                tests_passed = False
            elif forge_path is None:
                status = "tool_missing"
                feedback = ["Foundry project detected but forge executable is not available on PATH."]
                compiled = False
                tests_passed = False
            else:
                status = "ready_to_run"
                feedback = [
                    "Foundry project and forge executable detected.",
                    "The framework prepared the command but does not write generated PoCs into the project automatically.",
                ]
                compiled = False
                tests_passed = False

            results.append(
                FoundryRunResult(
                    draft_id=draft.id,
                    status=status,
                    command=command,
                    fork_block=draft.fork_block,
                    compiled=compiled,
                    tests_passed=tests_passed,
                    feedback=feedback,
                )
            )

        memory.foundry_results = results
        memory.notes.append(f"FoundrySandboxAgent produced {len(results)} sandbox feedback records.")


class PocFeedbackAgent:
    """LLM5 role: merge Foundry feedback into complete PoC plans."""

    def run(self, memory: WorkingMemory) -> None:
        feedback_by_draft = {result.draft_id: result for result in memory.foundry_results}
        completed = 0
        for draft in memory.poc_drafts:
            feedback = feedback_by_draft.get(draft.id)
            if feedback is None:
                continue
            draft.feedback = list(dict.fromkeys(draft.feedback + feedback.feedback))
            draft.status = "complete_poc_plan" if feedback.status in {"not_run", "tool_missing", "ready_to_run"} else feedback.status
            if feedback.command not in draft.next_steps:
                draft.next_steps.append(f"Sandbox command: {feedback.command}")
            if feedback.status != "ready_to_run":
                draft.next_steps.append("Install/configure Foundry or migrate this plan into the project's existing test runner.")
            completed += 1

        memory.notes.append(f"PocFeedbackAgent completed {completed} PoC plans from sandbox feedback.")


def _poc_code_template(root_cause: RootCauseAnalysis, historical_template: str) -> str:
    historical = historical_template or "function testExploitPath() public { /* arrange, act, assert */ }"
    evidence = "\n".join(f"    // evidence: {item}" for item in root_cause.evidence[:3])
    return (
        "// SPDX-License-Identifier: UNLICENSED\n"
        "pragma solidity ^0.8.20;\n\n"
        "import \"forge-std/Test.sol\";\n\n"
        "contract GeneratedExploitPlanTest is Test {\n"
        "    function testRootCauseReproduction() public {\n"
        f"        // category: {root_cause.category}\n"
        f"        // root cause: {root_cause.root_cause[:180]}\n"
        f"{evidence}\n"
        f"        // historical template: {historical}\n"
        "    }\n"
        "}\n"
    )


def _forge_command(draft: PocDraft) -> str:
    match_filter = draft.title.replace(" ", "_")[:48]
    fork = f" --fork-block-number {draft.fork_block}" if draft.fork_block is not None else ""
    return f"forge test --match-test {match_filter}{fork}"


def _make_id(seed: str, suffix: str) -> str:
    digest = hashlib.sha1(f"{seed}:{suffix}".encode("utf-8")).hexdigest()[:10]
    return f"{suffix}-{digest}"
