from __future__ import annotations

import hashlib

from .agents import (
    BusinessCompositionAgent as _BusinessCompositionAgent,
    BusinessConstraintValidatorAgent as _BusinessConstraintValidatorAgent,
    BusinessFlowGraphAgent as _BusinessFlowGraphAgent,
)
from .models import BusinessLogicUnit, WorkingMemory


class BusinessFlowGraphAgent(_BusinessFlowGraphAgent):
    """Blue-box Step 1: construct business flow nodes from functions and shared state."""


class BusinessLogicExtractionAgent:
    """LLM1 role: combine calls, inheritance, and state into business logic units."""

    def run(self, memory: WorkingMemory) -> None:
        call_edges_by_entry: dict[str, list[str]] = {}
        for edge in memory.call_edges:
            call_edges_by_entry.setdefault(edge.caller, []).append(edge.callee)

        inherited_context = [
            f"{edge.child} inherits {edge.parent} ({edge.path}:{edge.line_number})"
            for edge in memory.inheritance_edges
        ]

        units: list[BusinessLogicUnit] = []
        for flow in memory.business_flows:
            entry_points = list(flow.entry_points)
            callees = sorted(
                {
                    callee
                    for entry_point in entry_points
                    for callee in call_edges_by_entry.get(entry_point, [])
                }
            )
            unit = BusinessLogicUnit(
                id=_make_id(flow.id, "business_logic"),
                name=flow.name,
                entry_points=entry_points,
                call_edges=callees,
                state_variables=flow.state_variables,
                inherited_context=inherited_context,
                summary=_summarize_flow(flow.category, flow.name, flow.state_variables, callees),
                risk_focus=_risk_focus(flow.category, flow.keywords, flow.state_variables),
            )
            units.append(unit)

        memory.business_logic_units = units
        memory.notes.append(
            f"BusinessLogicExtractionAgent built {len(units)} business logic units from flows, calls, inheritance, and state."
        )


class BusinessCompositionAgent(_BusinessCompositionAgent):
    """LLM2 role: compose business logic units with audit-report vulnerability knowledge."""


class BusinessConstraintValidatorAgent(_BusinessConstraintValidatorAgent):
    """Step 2.b role: verify business-equivalence and security constraints."""


def _summarize_flow(category: str, name: str, state_variables: list[str], callees: list[str]) -> str:
    state = ", ".join(state_variables[:6]) or "no tracked state"
    calls = f" and calls {len(callees)} project function(s)" if callees else ""
    return f"`{name}` is a `{category}` business flow touching {state}{calls}."


def _risk_focus(category: str, keywords: list[str], state_variables: list[str]) -> list[str]:
    terms = {category, *keywords, *[variable.lower() for variable in state_variables]}
    focus: list[str] = []
    if terms & {"deposit", "withdraw", "mint", "redeem", "share", "shares", "supply"}:
        focus.append("business equivalence: asset/share accounting must be conserved")
    if terms & {"price", "quote", "oracle", "liquidity", "density"}:
        focus.append("security constraint: valuation inputs must resist manipulation and zero-state drift")
    if terms & {"owner", "admin", "upgrade", "initialize", "set"}:
        focus.append("security constraint: privileged mutations must be caller-restricted")
    if terms & {"transfer", "payment", "reward"}:
        focus.append("security constraint: external token/ETH interactions must preserve accounting")
    if not focus:
        focus.append("semantic consistency: state transitions should match peer flow guards")
    return focus


def _make_id(seed: str, suffix: str) -> str:
    digest = hashlib.sha1(f"{seed}:{suffix}".encode("utf-8")).hexdigest()[:10]
    return f"{suffix}-{digest}"
