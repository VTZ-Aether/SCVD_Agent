from __future__ import annotations

import json

from .context import build_finding_context
from .llm import LLMClient
from .models import WorkingMemory
from .prompts import LLM_REVIEW_SYSTEM_PROMPT, LLM_REVIEW_USER_PROMPT


class LLMReviewAgent:
    """Optional refinement layer for rule-generated vulnerability hypotheses."""

    def __init__(self, client: LLMClient, *, max_findings: int = 10) -> None:
        self.client = client
        self.max_findings = max_findings

    def run(self, memory: WorkingMemory) -> None:
        reviewed = 0
        kept = []
        for finding in memory.findings:
            if reviewed >= self.max_findings:
                kept.append(finding)
                continue
            reviewed += 1
            context = build_finding_context(memory, finding)
            user = LLM_REVIEW_USER_PROMPT.format(context=context)
            try:
                response = self.client.complete(
                    system=LLM_REVIEW_SYSTEM_PROMPT,
                    user=user,
                )
                decision = _parse_json_response(response)
            except Exception as exc:
                memory.notes.append(f"LLMReviewAgent skipped finding {finding.id}: {exc}")
                kept.append(finding)
                continue

            verdict = str(decision.get("verdict", "keep")).lower()
            if verdict == "discard":
                memory.notes.append(f"LLMReviewAgent discarded {finding.id}.")
                continue
            if verdict == "downgrade" and finding.severity in {"critical", "high"}:
                finding.severity = "medium"

            finding.title = str(decision.get("refined_title") or finding.title)
            finding.summary = str(decision.get("refined_summary") or finding.summary)
            finding.confidence = max(
                0.0,
                min(1.0, finding.confidence + float(decision.get("confidence_delta", 0.0))),
            )
            missing = decision.get("missing_evidence") or []
            steps = decision.get("next_validation_steps") or []
            for item in missing:
                finding.evidence.append(f"LLM missing evidence: {item}")
            for item in steps:
                if item not in finding.remediation:
                    finding.remediation.append(str(item))
            kept.append(finding)

        memory.findings = kept
        memory.notes.append(f"LLMReviewAgent reviewed {reviewed} finding candidates.")


def _parse_json_response(response: str) -> dict:
    response = response.strip()
    if response.startswith("```"):
        response = response.strip("`")
        if response.lower().startswith("json"):
            response = response[4:].strip()
    start = response.find("{")
    end = response.rfind("}")
    if start >= 0 and end >= start:
        response = response[start:end + 1]
    return json.loads(response)
