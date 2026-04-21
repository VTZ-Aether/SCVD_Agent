from __future__ import annotations

import re

from .knowledge import CURATED_AUDIT_KNOWLEDGE, retrieve_audit_knowledge
from .models import AttackPocRecord, RetrievedAttackPoc, WorkingMemory


CURATED_ATTACK_POC_KNOWLEDGE: list[AttackPocRecord] = [
    AttackPocRecord(
        id="defihack-erc4626-inflation",
        title="First depositor / donation share inflation PoC",
        source="DeFiHack-style historical exploit pattern",
        category="accounting",
        tactic="Seed vault with tiny shares, donate assets, then force later deposits to mint too few shares.",
        preconditions=[
            "Share conversion uses totalAssets/totalSupply without virtual offsets or minimum liquidity.",
            "Attacker can alter the asset/share ratio before victim deposit.",
        ],
        steps=[
            "Attacker deposits a tiny amount to become first depositor.",
            "Attacker donates assets directly or through an accounting path.",
            "Victim deposits at the skewed ratio.",
            "Attacker redeems inflated ownership.",
        ],
        indicators=["totalSupply", "totalAssets", "deposit", "redeem", "shares", "assets"],
        code_template="function testShareInflation() public { /* seed, donate, victim deposit, redeem */ }",
    ),
    AttackPocRecord(
        id="defihack-oracle-spot-manipulation",
        title="Flash-loan spot oracle manipulation PoC",
        source="DeFiHack-style historical exploit pattern",
        category="oracle",
        tactic="Use temporary liquidity movement to manipulate a spot price consumed by mint/borrow/liquidate logic.",
        preconditions=[
            "Protocol trusts getReserves, slot0, balanceOf, or another same-block manipulable price.",
            "Attacker can access flash liquidity or equivalent temporary capital.",
        ],
        steps=[
            "Borrow or source temporary liquidity.",
            "Move pool reserves or balances to skew the trusted price.",
            "Call the vulnerable valuation-dependent protocol entry point.",
            "Restore the pool and repay temporary liquidity.",
        ],
        indicators=["getReserves", "slot0", "balanceOf", "price", "quote", "borrow", "liquidate"],
        code_template="function testSpotOracleManipulation() public { /* flash loan, manipulate, exploit, repay */ }",
    ),
    AttackPocRecord(
        id="defihack-reentrancy-withdraw",
        title="Callback reentrancy withdraw PoC",
        source="DeFiHack-style historical exploit pattern",
        category="reentrancy",
        tactic="Re-enter during ETH/token callback before accounting state is closed.",
        preconditions=[
            "External interaction happens before all protective state updates.",
            "Attacker controls a callback-capable receiver or token hook.",
        ],
        steps=[
            "Deploy attacker receiver with callback.",
            "Enter the vulnerable withdraw/transfer flow.",
            "Re-enter a shared-state function during callback.",
            "Withdraw or observe stale accounting twice.",
        ],
        indicators=["call{value", ".call(", "safeTransfer", "transferFrom", "withdraw", "nonReentrant"],
        code_template="function testCallbackReentrancy() public { /* attacker receiver re-enters */ }",
    ),
    AttackPocRecord(
        id="defihack-weird-erc20",
        title="Weird ERC20 integration PoC",
        source="DeFiHack-style historical exploit pattern",
        category="external-call",
        tactic="Use non-standard token behavior to desynchronize credited accounting from actual balances.",
        preconditions=[
            "Protocol supports arbitrary tokens or does not enforce an allowlist.",
            "Deposit/withdraw accounting assumes standard ERC20 return values or exact transferred amount.",
        ],
        steps=[
            "Deploy a fee-on-transfer, rebasing, no-return, or callback token mock.",
            "Execute deposit/withdraw/payment flow.",
            "Compare credited accounting against actual token balance delta.",
        ],
        indicators=["transferFrom", "transfer(", "approve", "SafeERC20", "balanceBefore", "balanceAfter"],
        code_template="function testWeirdERC20Accounting() public { /* mock token + balance delta assertions */ }",
    ),
    AttackPocRecord(
        id="defihack-signature-replay",
        title="Signature replay PoC",
        source="DeFiHack-style historical exploit pattern",
        category="signature",
        tactic="Replay authorization across nonce, chain, contract, or expiration domains.",
        preconditions=[
            "Signed message omits nonce/domain/deadline, or nonce is not consumed.",
            "Attacker obtains a valid signature once.",
        ],
        steps=[
            "Submit a valid signed action.",
            "Replay the same signature in the same or different domain.",
            "Assert that unauthorized repeated execution succeeds or is blocked.",
        ],
        indicators=["ecrecover", "ECDSA", "nonces", "DOMAIN_SEPARATOR", "chainid", "deadline", "permit"],
        code_template="function testSignatureReplay() public { /* sign once, submit twice */ }",
    ),
    AttackPocRecord(
        id="defihack-dos-push-loop",
        title="Unbounded loop / push payment DoS PoC",
        source="DeFiHack-style historical exploit pattern",
        category="dos",
        tactic="Grow recipient or storage set until batch operation exceeds gas or reverts on one receiver.",
        preconditions=[
            "Loop iterates over user-growing storage or recipient arrays.",
            "Batch operation reverts on one recipient failure or cannot be paginated.",
        ],
        steps=[
            "Grow the collection to a large size.",
            "Insert a reverting receiver if push payments are used.",
            "Call the batch function and measure gas or revert behavior.",
        ],
        indicators=["for", "while", ".length", "transfer", "send", "recipients", "rewards"],
        code_template="function testBatchDoS() public { /* grow list, trigger batch */ }",
    ),
]


class AuditReportRAGAgent:
    """Top-left RAG: Code4rena/Sherlock-style audit-report vulnerability knowledge."""

    def __init__(self, *, max_records: int = 6) -> None:
        self.max_records = max_records

    def run(self, memory: WorkingMemory) -> None:
        memory.knowledge_base = CURATED_AUDIT_KNOWLEDGE
        memory.retrieved_knowledge = retrieve_audit_knowledge(memory, limit=self.max_records)
        memory.notes.append(
            f"AuditReportRAGAgent retrieved {len(memory.retrieved_knowledge)} audit-report knowledge records."
        )


class AttackPocRAGAgent:
    """Top-right RAG: historical DeFiHack-style attack PoC knowledge."""

    def __init__(self, *, max_records: int = 4) -> None:
        self.max_records = max_records

    def run(self, memory: WorkingMemory) -> None:
        memory.attack_poc_knowledge_base = CURATED_ATTACK_POC_KNOWLEDGE
        memory.retrieved_attack_pocs = retrieve_attack_pocs(memory, limit=self.max_records)
        memory.notes.append(
            f"AttackPocRAGAgent retrieved {len(memory.retrieved_attack_pocs)} historical attack PoC records."
        )


def retrieve_attack_pocs(memory: WorkingMemory, *, limit: int = 4) -> list[RetrievedAttackPoc]:
    corpus = _memory_corpus(memory)
    scored: list[RetrievedAttackPoc] = []
    for record in CURATED_ATTACK_POC_KNOWLEDGE:
        score, matched = _score_attack_record(corpus, record)
        if score <= 0:
            continue
        scored.append(
            RetrievedAttackPoc(
                poc_id=record.id,
                score=score,
                rationale=f"Matched cues: {', '.join(matched[:8])}",
            )
        )
    scored.sort(key=lambda item: item.score, reverse=True)
    return scored[:limit]


def attack_poc_by_id(records: list[AttackPocRecord]) -> dict[str, AttackPocRecord]:
    return {record.id: record for record in records}


def _memory_corpus(memory: WorkingMemory) -> set[str]:
    words: set[str] = set()
    for function in memory.functions:
        words.update(_split_words(function.name))
        words.update(function.economic_keywords)
        words.update(_split_words(" ".join(function.state_reads | function.state_writes)))
    for finding in memory.findings:
        words.update(_split_words(finding.title))
        words.update(_split_words(finding.summary))
        words.update(finding.tags)
        words.update(_split_words(" ".join(finding.evidence[:4])))
    for document in memory.documents:
        words.update(_split_words(document.title))
        words.update(_split_words(document.text[:1200]))
    return words


def _score_attack_record(corpus: set[str], record: AttackPocRecord) -> tuple[float, list[str]]:
    weighted_terms: list[tuple[str, float]] = [
        (record.category, 2.0),
        (record.tactic, 1.5),
        (" ".join(record.indicators), 2.5),
        (" ".join(record.preconditions), 1.25),
        (" ".join(record.steps), 1.0),
    ]
    score = 0.0
    matched: list[str] = []
    for term, weight in weighted_terms:
        term_words = _split_words(term)
        if not term_words:
            continue
        overlap = corpus & term_words
        if not overlap:
            continue
        score += weight * (len(overlap) / len(term_words))
        matched.extend(sorted(overlap))
    return score, list(dict.fromkeys(matched))


def _split_words(text: str) -> set[str]:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return {
        word.lower()
        for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", normalized)
        if len(word) > 2
    }
