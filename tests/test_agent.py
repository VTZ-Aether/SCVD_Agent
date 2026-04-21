from __future__ import annotations

import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from scvd_agent.api import scan_contract_project
from scvd_agent.orchestrator import ArithmeticAuditAgent


FIXTURES = Path(__file__).parent / "fixtures"


class ArithmeticAuditAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = ArithmeticAuditAgent()

    def test_detects_cross_function_arithmetic_drift(self) -> None:
        memory = self.agent.run(FIXTURES / "vulnerable")
        titles = [finding.title for finding in memory.findings]
        validation_statuses = {result.status for result in memory.validation_results}
        self.assertTrue(
            any("Workflow-level arithmetic drift" in title for title in titles),
            msg=f"Expected a workflow-level finding, got: {titles}",
        )
        self.assertTrue(
            any("rounding" in title.lower() for title in titles),
            msg=f"Expected a rounding-related finding, got: {titles}",
        )
        self.assertTrue(memory.retrieved_knowledge, msg="Expected RAG knowledge retrieval results.")
        self.assertTrue(memory.retrieved_attack_pocs, msg="Expected historical attack PoC retrieval results.")
        self.assertTrue(memory.business_flows, msg="Expected business flow graph nodes.")
        self.assertTrue(memory.business_logic_units, msg="Expected business logic units.")
        self.assertTrue(memory.audit_tasks, msg="Expected semantic-vulnerability audit tasks.")
        self.assertTrue(
            any(constraint.status == "violated" for constraint in memory.business_constraints),
            msg=f"Expected a violated business constraint, got: {memory.business_constraints}",
        )
        self.assertIn(
            "static_validated",
            validation_statuses,
            msg=f"Expected at least one statically validated finding, got: {validation_statuses}",
        )
        static_result = next(
            result for result in memory.validation_results if result.status == "static_validated"
        )
        self.assertTrue(static_result.preconditions, msg="Expected validation preconditions.")
        self.assertTrue(static_result.false_positive_checks, msg="Expected false-positive checks.")
        self.assertTrue(static_result.attack_path, msg="Expected an attack/validation path.")
        self.assertTrue(static_result.next_steps, msg="Expected next validation steps.")
        self.assertTrue(memory.root_causes, msg="Expected root-cause records.")
        self.assertTrue(memory.poc_drafts, msg="Expected PoC drafts.")
        self.assertTrue(memory.foundry_results, msg="Expected Foundry sandbox feedback.")
        self.assertTrue(memory.patch_candidates, msg="Expected patch candidates.")
        self.assertTrue(memory.dynamic_validation_results, msg="Expected dynamic validation plans.")
        self.assertTrue(memory.security_patches, msg="Expected security patch plans.")

    def test_safe_fixture_avoids_high_workflow_finding(self) -> None:
        memory = self.agent.run(FIXTURES / "safe")
        high_titles = [
            finding.title for finding in memory.findings if finding.severity in {"high", "critical"}
        ]
        self.assertFalse(
            any("Workflow-level arithmetic drift" in title for title in high_titles),
            msg=f"Did not expect a high workflow drift finding, got: {high_titles}",
        )
        self.assertFalse(
            any("Business constraint violation" in title for title in high_titles),
            msg=f"Did not expect a high business-constraint finding, got: {high_titles}",
        )
        self.assertTrue(
            any(constraint.status == "satisfied" for constraint in memory.business_constraints),
            msg=f"Expected the safe fixture to satisfy at least one business constraint, got: {memory.business_constraints}",
        )

    def test_api_returns_stable_io_envelope(self) -> None:
        with TemporaryDirectory() as temp_dir:
            result = scan_contract_project(
                {
                    "target": str(FIXTURES / "vulnerable"),
                    "out_dir": temp_dir,
                    "report_prefix": "io_contract",
                    "output_formats": ["json"],
                    "options": {
                        "max_hotspots": 30,
                        "max_knowledge_records": 6,
                        "max_attack_poc_records": 4,
                    },
                }
            )
            self.assertEqual(result["schema_version"], "scvd.multiagent.io.v1")
            self.assertIn("inputs", result)
            self.assertIn("artifacts", result)
            self.assertIn("summary", result)
            self.assertIn("outputs", result)
            self.assertIn("working_memory", result)
            self.assertIn("project", result["outputs"])
            self.assertIn("rag", result["outputs"])
            self.assertIn("analysis", result["outputs"])
            self.assertIn("poc", result["outputs"])
            self.assertIn("patches", result["outputs"])
            self.assertIsNone(result["artifacts"]["markdown_report"])
            self.assertTrue(Path(result["artifacts"]["json_report"]).exists())


if __name__ == "__main__":
    unittest.main()
