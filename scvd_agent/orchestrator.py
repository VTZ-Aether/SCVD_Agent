from __future__ import annotations

from pathlib import Path

from .agents import (
    BusinessCompositionAgent,
    BusinessConstraintValidatorAgent,
    BusinessFlowGraphAgent,
    HotspotExtractionAgent,
    HypothesisAgent,
    ProjectProfilerAgent,
    RAGKnowledgeAgent,
    ReflectionAgent,
    ValidationAgent,
    VulnerabilityReasoningAgent,
    WorkflowMapperAgent,
)
from .llm import build_llm_client
from .llm_agents import LLMReviewAgent
from .models import WorkingMemory
from .schemas import ScanOptions


class ArithmeticAuditAgent:
    """Agentic SCVD pipeline with RAG, business-flow reasoning, and static validation."""

    def __init__(self, options: ScanOptions | None = None) -> None:
        self.options = options or ScanOptions()
        self.project_profiler = ProjectProfilerAgent()
        self.rag_knowledge_agent = RAGKnowledgeAgent(max_records=self.options.max_knowledge_records)
        self.business_flow_graph_agent = BusinessFlowGraphAgent()
        self.business_composition_agent = BusinessCompositionAgent()
        self.business_constraint_validator_agent = BusinessConstraintValidatorAgent()
        self.hotspot_extractor = HotspotExtractionAgent()
        self.workflow_mapper = WorkflowMapperAgent()
        self.hypothesis_agent = HypothesisAgent()
        self.vulnerability_reasoning_agent = VulnerabilityReasoningAgent()
        self.reflection_agent = ReflectionAgent()
        self.validation_agent = ValidationAgent()

    def run(self, target_path: str | Path) -> WorkingMemory:
        root = Path(target_path).resolve()
        memory = self.project_profiler.run(root)
        self.rag_knowledge_agent.run(memory)
        self.business_flow_graph_agent.run(memory)
        self.business_composition_agent.run(memory)
        self.business_constraint_validator_agent.run(memory)
        self.hotspot_extractor.run(memory)
        memory.hotspots = memory.hotspots[: self.options.max_hotspots]
        self.workflow_mapper.run(memory)
        self.hypothesis_agent.run(memory)
        self.vulnerability_reasoning_agent.run(memory)
        self.reflection_agent.run(memory)
        self.validation_agent.run(memory)
        if self.options.llm.enabled:
            llm_client = build_llm_client(self.options.llm)
            llm_review_agent = LLMReviewAgent(llm_client)
            llm_review_agent.run(memory)
            self.reflection_agent.run(memory)
            self.validation_agent.run(memory)
        return memory
