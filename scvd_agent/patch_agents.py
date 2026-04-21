from __future__ import annotations

import hashlib

from .models import DynamicValidationResult, PatchCandidate, SecurityPatch, WorkingMemory


class PatchGenerationAgent:
    """LLM6/LLM7 role: multi-agent patch generation from business and security constraints."""

    def run(self, memory: WorkingMemory) -> None:
        validations = {result.finding_id: result for result in memory.validation_results}
        candidates: list[PatchCandidate] = []

        for finding in memory.findings:
            validation = validations.get(finding.id)
            business_constraints = validation.preconditions if validation else []
            security_constraints = validation.false_positive_checks if validation else []
            strategy, diff = _patch_strategy_and_diff(finding.tags)
            candidates.append(
                PatchCandidate(
                    id=_make_id(finding.id, "patch_candidate"),
                    finding_id=finding.id,
                    strategy=strategy,
                    business_constraints=business_constraints,
                    security_constraints=security_constraints,
                    diff=diff,
                    rationale=(
                        "Patch candidate preserves the business logic while adding the minimum security "
                        "constraint required by the validation plan."
                    ),
                    status="candidate",
                )
            )

        memory.patch_candidates = candidates
        memory.notes.append(f"PatchGenerationAgent generated {len(candidates)} multi-agent patch candidates.")


class PatchDynamicValidationAgent:
    """Green-box dynamic validation planner: validates patch candidates against generated checks."""

    def run(self, memory: WorkingMemory) -> None:
        validations = {result.finding_id: result for result in memory.validation_results}
        dynamic_results: list[DynamicValidationResult] = []
        security_patches: list[SecurityPatch] = []

        for candidate in memory.patch_candidates:
            validation = validations.get(candidate.finding_id)
            checks = []
            if validation is not None:
                checks.extend(validation.next_steps)
                checks.extend(validation.false_positive_checks[:2])
            checks.append("Run regression tests proving the original exploit path is blocked.")
            checks.append("Run business-equivalence tests proving intended user flows still work.")

            status = "ready_for_dynamic_validation" if checks else "needs_validation_plan"
            feedback = [
                "Patch has not been applied automatically.",
                "Dynamic validation requires executing the generated checks in the target test framework.",
            ]
            dynamic_results.append(
                DynamicValidationResult(
                    patch_id=candidate.id,
                    status=status,
                    checks=list(dict.fromkeys(checks)),
                    feedback=feedback,
                )
            )
            security_patches.append(
                SecurityPatch(
                    id=_make_id(candidate.id, "security_patch"),
                    finding_id=candidate.finding_id,
                    patch_candidate_id=candidate.id,
                    summary=candidate.strategy,
                    diff=candidate.diff,
                    validation_status=status,
                    residual_risk=[
                        "Generated patch is a plan, not an applied source change.",
                        "Manual review is required for inherited guards, integration-specific invariants, and gas impact.",
                    ],
                )
            )

        memory.dynamic_validation_results = dynamic_results
        memory.security_patches = security_patches
        memory.notes.append(
            f"PatchDynamicValidationAgent prepared {len(security_patches)} security patch plans with dynamic checks."
        )


def _patch_strategy_and_diff(tags: list[str]) -> tuple[str, str]:
    tag_set = set(tags)
    if tag_set & {"accounting", "bootstrap", "boundary_state"}:
        return (
            "Add explicit bootstrap/zero-state guards and virtual liquidity or minimum-share protection.",
            "+ require(totalSupply > 0, \"zero supply\");\n+ // consider virtual shares/assets or minimum liquidity for first deposits",
        )
    if tag_set & {"arithmetic", "rounding", "precision"}:
        return (
            "Replace implicit integer division with mulDiv-style helpers and documented rounding direction.",
            "- amount = a * b / denominator;\n+ amount = Math.mulDiv(a, b, denominator, Math.Rounding.Ceil);",
        )
    if "oracle" in tag_set:
        return (
            "Replace spot/balance-derived valuation with freshness-checked TWAP or Chainlink-style oracle guards.",
            "+ require(block.timestamp - updatedAt <= MAX_ORACLE_DELAY, \"stale oracle\");\n+ require(_withinDeviation(price), \"oracle deviation\");",
        )
    if "access-control" in tag_set:
        return (
            "Add explicit role modifier or msg.sender authorization to privileged mutation.",
            "- function setParam(uint256 value) external {\n+ function setParam(uint256 value) external onlyOwner {",
        )
    if "reentrancy" in tag_set:
        return (
            "Apply checks-effects-interactions and nonReentrant guards around external interactions.",
            "+ function withdraw(uint256 amount) external nonReentrant {\n+   // effects before interactions",
        )
    if "external-call" in tag_set:
        return (
            "Use SafeERC20 and balance-delta accounting for token transfers.",
            "+ uint256 beforeBal = token.balanceOf(address(this));\n+ token.safeTransferFrom(msg.sender, address(this), amount);\n+ uint256 received = token.balanceOf(address(this)) - beforeBal;",
        )
    if "signature" in tag_set:
        return (
            "Use complete EIP-712 domain separation, nonce consumption, deadline, and signer checks.",
            "+ require(block.timestamp <= deadline, \"expired\");\n+ _useNonce(signer);\n+ require(recovered == signer && recovered != address(0), \"bad sig\");",
        )
    if "dos" in tag_set:
        return (
            "Replace unbounded push loops with bounded pagination or pull-payment withdrawals.",
            "+ function process(uint256 start, uint256 limit) external { /* bounded batch */ }",
        )
    if "upgradeability" in tag_set:
        return (
            "Add initializer disabling, upgrade authorization, and storage layout checks.",
            "+ constructor() { _disableInitializers(); }\n+ function _authorizeUpgrade(address) internal override onlyOwner {}",
        )
    return (
        "Add the missing semantic guard and regression test around the affected state transition.",
        "+ require(_businessInvariantHolds(), \"invariant\");",
    )


def _make_id(seed: str, suffix: str) -> str:
    digest = hashlib.sha1(f"{seed}:{suffix}".encode("utf-8")).hexdigest()[:10]
    return f"{suffix}-{digest}"
