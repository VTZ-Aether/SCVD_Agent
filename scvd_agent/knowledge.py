from __future__ import annotations

import re

from .models import AuditKnowledgeRecord, RetrievedKnowledge, WorkingMemory


ECONOMIC_KEYWORDS = {
    "asset",
    "assets",
    "balance",
    "collateral",
    "convert",
    "density",
    "deposit",
    "fee",
    "index",
    "interest",
    "liquidity",
    "lp",
    "mint",
    "output",
    "pool",
    "price",
    "quote",
    "rate",
    "rebalance",
    "redeem",
    "reserve",
    "reward",
    "share",
    "shares",
    "supply",
    "swap",
    "totalassets",
    "totalshares",
    "totalsupply",
    "value",
    "vault",
    "withdraw",
}

ROUNDING_UP_MARKERS = {
    "ceildiv",
    "muldivup",
    "divwadup",
    "mulwadup",
    "roundup",
    "pow_up",
}

ROUNDING_DOWN_MARKERS = {
    "muldivdown",
    "divwaddown",
    "mulwaddown",
    "rounddown",
    "pow_down",
}

PRECISION_MARKERS = {
    "1e18",
    "1e27",
    "1e12",
    "1e8",
    "q96",
    "precision",
    "wad",
    "ray",
    "scale",
    "scaler",
    "decimals",
}

VALUATION_KEYWORDS = {
    "estimate",
    "liquidity",
    "price",
    "quote",
    "value",
    "preview",
    "convert",
}

WORKFLOW_KEYWORDS = {
    "deposit",
    "withdraw",
    "mint",
    "burn",
    "swap",
    "redeem",
    "rebalance",
    "settle",
    "update",
    "quote",
    "preview",
}

RISKY_MARKERS = {
    "unchecked",
    "unsafe_",
    "assembly",
}

STATE_SENSITIVE_VARIABLES = {
    "balance",
    "reserve",
    "liquidity",
    "supply",
    "share",
    "index",
    "rate",
    "price",
    "density",
    "amount",
}

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


CURATED_AUDIT_KNOWLEDGE: list[AuditKnowledgeRecord] = [
    AuditKnowledgeRecord(
        id="c4-share-inflation-bootstrap",
        title="Proportional-share accounting bootstrap and first-depositor attacks",
        source="Code4rena / Knowdit-style DeFi semantic summary",
        category="accounting",
        severity_hint="high",
        semantics=["vault share accounting", "proportional shares", "deposit mint redeem withdraw"],
        vulnerability_patterns=[
            "first depositor can skew share-to-asset ratio",
            "zero or near-zero supply denominator amplifies rounding",
            "donation or bootstrap imbalance causes later users to receive mispriced shares",
        ],
        detection_cues=["totalSupply", "totalAssets", "shares", "assets", "deposit", "mint", "redeem", "withdraw", "/"],
        constraints=[
            "Bootstrap states must be explicitly handled before share or asset conversion.",
            "Conversion functions must define and test the intended rounding direction.",
            "Donations or tiny first deposits must not let one actor capture later deposits.",
        ],
        remediation=[
            "Add minimum liquidity or virtual shares/assets.",
            "Guard zero-supply branches explicitly.",
            "Test first-depositor and donation scenarios with a high-precision reference model.",
        ],
    ),
    AuditKnowledgeRecord(
        id="sherlock-division-before-multiplication",
        title="Division-before-multiplication precision loss in economic formulas",
        source="Sherlock / SCV precision-loss pattern",
        category="arithmetic",
        severity_hint="medium",
        semantics=["fee calculation", "rate calculation", "reward accounting"],
        vulnerability_patterns=[
            "intermediate division truncates before later multiplication",
            "small user amounts round to zero",
            "repeated interactions accumulate dust drift",
        ],
        detection_cues=["/", "*", "fee", "rate", "reward", "index", "precision", "wad", "ray"],
        constraints=[
            "Economic formulas should multiply before division or use a checked mulDiv helper.",
            "Precision constants must be visible at token/rate/index boundaries.",
        ],
        remediation=[
            "Use mulDiv-style helpers with documented rounding direction.",
            "Add fuzz tests for tiny amounts, maximum values, and mixed-decimal assets.",
        ],
    ),
    AuditKnowledgeRecord(
        id="c4-oracle-spot-price",
        title="Spot-price or balance-derived oracle manipulation",
        source="Code4rena / QuillShield oracle-flashloan pattern",
        category="oracle",
        severity_hint="high",
        semantics=["oracle price", "AMM reserves", "valuation", "liquidation"],
        vulnerability_patterns=[
            "price reads from getReserves, slot0, balanceOf, or a single pool spot quote",
            "flash loan or donation changes the price inside one transaction",
            "borrow, liquidate, mint, or redeem path trusts the manipulated value",
        ],
        detection_cues=["getReserves", "slot0", "balanceOf", "price", "quote", "oracle", "liquidate", "borrow"],
        constraints=[
            "Critical valuation paths must not depend on single-transaction manipulable spot prices.",
            "Oracle reads should include freshness, deviation, and source-quality checks where applicable.",
        ],
        remediation=[
            "Prefer validated Chainlink or sufficiently long TWAP with circuit breakers.",
            "Add flash-loan manipulation tests for borrow, liquidate, mint, and redeem paths.",
        ],
    ),
    AuditKnowledgeRecord(
        id="sherlock-missing-access-control",
        title="Privileged state mutation without consistent access control",
        source="Sherlock / QuillShield semantic guard pattern",
        category="access-control",
        severity_hint="high",
        semantics=["admin operation", "parameter setter", "mint pause upgrade"],
        vulnerability_patterns=[
            "state-changing privileged function lacks onlyOwner/onlyRole or msg.sender check",
            "one function bypasses guards consistently used by peer functions",
            "initializer can be called by an unintended actor",
        ],
        detection_cues=["owner", "admin", "onlyOwner", "onlyRole", "set", "mint", "pause", "initialize", "upgrade"],
        constraints=[
            "Functions mutating admin-controlled state must have explicit caller restrictions.",
            "Guard patterns should be consistent across functions that write the same critical state.",
        ],
        remediation=[
            "Add role modifiers or explicit caller checks.",
            "Add negative authorization tests for every privileged entry point.",
        ],
    ),
    AuditKnowledgeRecord(
        id="c4-reentrancy-cei",
        title="External interaction before completing effects",
        source="Code4rena / QuillShield reentrancy pattern",
        category="reentrancy",
        severity_hint="high",
        semantics=["withdraw", "transfer", "callback", "cross-function shared state"],
        vulnerability_patterns=[
            "external call occurs before state writes that close the accounting window",
            "other public functions can observe or mutate stale state during callback",
            "ERC777/ERC1155/ERC721 callbacks re-enter the protocol",
        ],
        detection_cues=["call{value", ".call(", "transfer", "safeTransfer", "tokensReceived", "nonReentrant"],
        constraints=[
            "Effects that protect value accounting should happen before external interactions.",
            "All reentrant entry points touching shared state should be consistently guarded.",
        ],
        remediation=[
            "Apply checks-effects-interactions and nonReentrant where needed.",
            "Add callback-based tests for token and ETH transfers.",
        ],
    ),
    AuditKnowledgeRecord(
        id="sherlock-weird-erc20",
        title="External token integration assumes standard ERC20 behavior",
        source="Sherlock / Weird ERC20 checklist",
        category="external-call",
        severity_hint="medium",
        semantics=["token transfer", "deposit", "withdraw", "payment distribution"],
        vulnerability_patterns=[
            "raw transfer/transferFrom return values are not safely handled",
            "fee-on-transfer token credits more than actual received",
            "rebasing, blacklist, callback, or non-zero approval behavior breaks accounting",
        ],
        detection_cues=["transferFrom", "transfer(", "approve", "SafeERC20", "balanceBefore", "balanceAfter"],
        constraints=[
            "Token deposits should credit actual balance deltas when arbitrary tokens are supported.",
            "External token calls should use safe wrappers or explicit low-level return handling.",
        ],
        remediation=[
            "Use SafeERC20 and balance-delta accounting for deposits.",
            "Document unsupported token classes and enforce allowlists if needed.",
        ],
    ),
    AuditKnowledgeRecord(
        id="c4-signature-replay",
        title="Signature replay across nonce, contract, or chain domains",
        source="Code4rena / signature replay checklist",
        category="signature",
        severity_hint="high",
        semantics=["permit", "meta transaction", "off-chain authorization"],
        vulnerability_patterns=[
            "signed message omits nonce",
            "signed message omits address(this) or chainid",
            "deadline or ecrecover zero-address and malleability checks are missing",
        ],
        detection_cues=["ecrecover", "ECDSA", "nonces", "DOMAIN_SEPARATOR", "chainid", "deadline", "permit"],
        constraints=[
            "Signatures should be domain-separated by chain id and verifying contract.",
            "Each authorization should consume a nonce and enforce an expiration window.",
        ],
        remediation=[
            "Use EIP-712 with complete domain fields.",
            "Track nonces by signer and verify deadline, recovered address, and malleability constraints.",
        ],
    ),
    AuditKnowledgeRecord(
        id="sherlock-dos-loop",
        title="Unbounded loop or push-payment DoS",
        source="Sherlock / SCV DoS pattern",
        category="dos",
        severity_hint="medium",
        semantics=["batch operation", "reward distribution", "recipient loop"],
        vulnerability_patterns=[
            "loop over user-growing storage can exceed block gas limit",
            "single reverting external transfer blocks the whole batch",
            "storage bloat makes critical functions uncallable",
        ],
        detection_cues=["for", "while", ".length", "transfer", "send", "recipients", "rewards"],
        constraints=[
            "User-growing collections should use pagination or pull-based withdrawals.",
            "Batch payment failures should not permanently block unrelated recipients.",
        ],
        remediation=[
            "Use pull payments, bounded batches, or checkpointed pagination.",
            "Handle per-recipient failures without reverting the entire distribution when safe.",
        ],
    ),
    AuditKnowledgeRecord(
        id="c4-proxy-initialization",
        title="Upgradeable proxy initialization and storage-layout safety",
        source="Code4rena / Trail of Bits upgradeability checklist",
        category="upgradeability",
        severity_hint="high",
        semantics=["proxy", "initializer", "upgrade", "delegatecall storage"],
        vulnerability_patterns=[
            "initializer can be called more than once or on implementation",
            "upgrade authorization is missing",
            "implementation version changes storage slot order",
        ],
        detection_cues=["delegatecall", "initializer", "reinitializer", "upgradeTo", "UUPS", "Proxy", "__gap"],
        constraints=[
            "Implementation contracts should disable initializers when appropriate.",
            "Upgrade paths must be authorized and storage-compatible.",
        ],
        remediation=[
            "Add _disableInitializers to implementation constructors where applicable.",
            "Run storage layout checks and upgrade authorization tests.",
        ],
    ),
]


def retrieve_audit_knowledge(memory: WorkingMemory, *, limit: int = 6) -> list[RetrievedKnowledge]:
    corpus = _project_corpus(memory)
    scored: list[RetrievedKnowledge] = []
    for record in CURATED_AUDIT_KNOWLEDGE:
        score, matched = _score_record(corpus, record)
        if score <= 0:
            continue
        scored.append(
            RetrievedKnowledge(
                knowledge_id=record.id,
                score=score,
                rationale=f"Matched cues: {', '.join(matched[:8])}",
            )
        )
    scored.sort(key=lambda item: item.score, reverse=True)
    return scored[:limit]


def knowledge_by_id(records: list[AuditKnowledgeRecord]) -> dict[str, AuditKnowledgeRecord]:
    return {record.id: record for record in records}


def _project_corpus(memory: WorkingMemory) -> set[str]:
    words: set[str] = set()
    for keyword in memory.profile.protocol_keywords | memory.profile.economic_state_vars:
        words.update(_split_words(keyword))
    for document in memory.documents:
        words.update(_split_words(document.title))
        words.update(_split_words(document.text[:2000]))
    for function in memory.functions:
        words.update(_split_words(function.name))
        words.update(function.economic_keywords)
        words.update(_split_words(" ".join(function.state_reads | function.state_writes)))
        for site in function.arithmetic_sites[:5]:
            words.update(_split_words(site.code))
    return words


def _score_record(corpus: set[str], record: AuditKnowledgeRecord) -> tuple[float, list[str]]:
    weighted_terms: list[tuple[str, float]] = []
    weighted_terms.extend((term, 2.0) for term in record.semantics)
    weighted_terms.extend((term, 1.5) for term in record.vulnerability_patterns)
    weighted_terms.extend((term, 2.5) for term in record.detection_cues)
    weighted_terms.append((record.category, 1.5))

    score = 0.0
    matched: list[str] = []
    for term, weight in weighted_terms:
        term_words = _split_words(term)
        if not term_words:
            continue
        overlap = corpus & term_words
        if not overlap:
            continue
        ratio = len(overlap) / len(term_words)
        score += weight * ratio
        matched.extend(sorted(overlap))
    return score, list(dict.fromkeys(matched))


def _split_words(text: str) -> set[str]:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return {
        word.lower()
        for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", normalized)
        if len(word) > 2
    }
