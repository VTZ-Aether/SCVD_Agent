from __future__ import annotations

from pathlib import Path

from .business_agents import (
    BusinessCompositionAgent,
    BusinessConstraintValidatorAgent,
    BusinessFlowGraphAgent,
    BusinessLogicExtractionAgent,
)
from .patch_agents import PatchDynamicValidationAgent, PatchGenerationAgent
from .poc_agents import FoundrySandboxAgent, PocFeedbackAgent, PocPlanningAgent
from .project_agents import CodeStructureAgent, ProjectProfilerAgent
from .rag_agents import AttackPocRAGAgent, AuditReportRAGAgent
from .reasoning_agents import (
    HotspotExtractionAgent,
    HypothesisAgent,
    ReflectionAgent,
    RootCauseReasoningAgent,
    VulnerabilityReasoningAgent,
    WorkflowMapperAgent,
)
from .validation_agents import ValidationAgent
from .llm import build_llm_client
from .llm_agents import LLMReviewAgent
from .models import WorkingMemory
from .schemas import ScanOptions


class SCVDMultiAgentFramework:
    """Multi-agent SCVD pipeline with dual RAG, PoC planning, validation, and patch planning."""

    def __init__(self, options: ScanOptions | None = None) -> None:
        self.options = options or ScanOptions()
        self.project_profiler = ProjectProfilerAgent()
        self.code_structure_agent = CodeStructureAgent()
        self.audit_report_rag_agent = AuditReportRAGAgent(max_records=self.options.max_knowledge_records)
        self.business_flow_graph_agent = BusinessFlowGraphAgent()
        self.business_logic_extraction_agent = BusinessLogicExtractionAgent()
        self.business_composition_agent = BusinessCompositionAgent()
        self.business_constraint_validator_agent = BusinessConstraintValidatorAgent()
        self.hotspot_extractor = HotspotExtractionAgent()
        self.workflow_mapper = WorkflowMapperAgent()
        self.hypothesis_agent = HypothesisAgent()
        self.vulnerability_reasoning_agent = VulnerabilityReasoningAgent()
        self.reflection_agent = ReflectionAgent()
        self.attack_poc_rag_agent = AttackPocRAGAgent(max_records=self.options.max_attack_poc_records)
        self.root_cause_reasoning_agent = RootCauseReasoningAgent()
        self.validation_agent = ValidationAgent()
        self.poc_planning_agent = PocPlanningAgent()
        self.foundry_sandbox_agent = FoundrySandboxAgent()
        self.poc_feedback_agent = PocFeedbackAgent()
        self.patch_generation_agent = PatchGenerationAgent()
        self.patch_dynamic_validation_agent = PatchDynamicValidationAgent()

    def run(
        self,
        target_path: str | Path,
        *,
        document_paths: list[str | Path] | None = None,
        scope_files: list[str | Path] | None = None,
    ) -> WorkingMemory:
        root = Path(target_path).resolve()
        memory = self.project_profiler.run(
            root,
            document_paths=[Path(path).resolve() for path in document_paths or []],
        )
        if scope_files:
            normalized_scope = [str(Path(path).resolve()) for path in scope_files]
            memory.notes.append(
                "Scope files requested: " + ", ".join(normalized_scope)
            )
        self.code_structure_agent.run(memory)
        self.audit_report_rag_agent.run(memory)
        self.business_flow_graph_agent.run(memory)
        self.business_logic_extraction_agent.run(memory)
        self.business_composition_agent.run(memory)
        self.business_constraint_validator_agent.run(memory)
        self.hotspot_extractor.run(memory)
        memory.hotspots = memory.hotspots[: self.options.max_hotspots]
        self.workflow_mapper.run(memory)
        self.hypothesis_agent.run(memory)
        self.vulnerability_reasoning_agent.run(memory)
        self.reflection_agent.run(memory)
        if self.options.llm.enabled:
            llm_client = build_llm_client(self.options.llm)
            llm_review_agent = LLMReviewAgent(llm_client)
            llm_review_agent.run(memory)
            self.reflection_agent.run(memory)
        self.attack_poc_rag_agent.run(memory)
        self.root_cause_reasoning_agent.run(memory)
        self.validation_agent.run(memory)
        self.poc_planning_agent.run(memory)
        self.foundry_sandbox_agent run(memory)
        self.poc_feedback_agent.run(memory)
        self.patch_generation_agent.run(memory)
        self.patch_dynamic_validation_agent.run(memory)
        return memory


ArithmeticAuditAgent = SCVDMultiAgentFramework
