"""Intent classification and route confidence scoring.

This module exists because of a specific Copilot Studio limitation: Copilot
Studio does not expose its intent-matching confidence to topics as a variable.
The assignment requires "if confidence < threshold, route to live agent queue",
which cannot be built on a number the platform will not give you.

So confidence is computed here and returned as a connector output. The Copilot
Studio topic branches on `route_confidence`, which makes the requirement
actually implementable rather than aspirational.

Scoring is deterministic keyword-weight matching, not a model. Same reasoning
as the rewriter: it is auditable, testable, and adds no injection surface. The
score is intentionally conservative -- an unsure agent escalating to a human is
a good outcome in retail banking, whereas a confident wrong answer is not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Scenario -> (term, weight). Weights reflect how strongly a term implies the
# intent: "chargeback" is nearly conclusive for a dispute, "payment" is weak
# because it appears across every scenario.
SIGNALS: dict[str, dict[str, float]] = {
    "balance_inquiry": {
        "balance": 0.55, "how much": 0.45, "available": 0.30, "cleared": 0.30,
        "statement": 0.30, "transaction history": 0.40, "recent transaction": 0.40,
        "in my account": 0.40, "overdraft": 0.25, "funds": 0.30, "money left": 0.45,
        "spent": 0.20, "credit": 0.10, "direct debit": 0.20, "standing order": 0.20,
    },
    "loan_application": {
        "loan": 0.55, "mortgage": 0.55, "borrow": 0.45, "lending": 0.40,
        "application": 0.30, "apply": 0.30, "approved": 0.30, "eligibility": 0.45,
        "interest rate": 0.35, "repayment": 0.40, "credit check": 0.40,
        "affordability": 0.45, "remortgage": 0.55, "term": 0.15, "apr": 0.30,
    },
    "transaction_dispute": {
        "dispute": 0.60, "chargeback": 0.65, "fraud": 0.55, "unauthorised": 0.60,
        "unauthorized": 0.60, "do not recognise": 0.60, "dont recognise": 0.60,
        "do not recognize": 0.60, "not recognise": 0.50, "unrecognised": 0.55,
        "scam": 0.50, "stolen": 0.50, "refund": 0.40, "wrong amount": 0.45,
        "charged twice": 0.55, "double charged": 0.55, "someone has used": 0.55,
        "didnt make": 0.45, "did not make": 0.45, "report": 0.20,
    },
    "branch_locator": {
        "branch": 0.55, "cash machine": 0.55, "atm": 0.50, "cashpoint": 0.55,
        "opening hours": 0.55, "open on": 0.35, "nearest": 0.45, "near me": 0.45,
        "location": 0.35, "address": 0.30, "where is": 0.40, "directions": 0.40,
        "wheelchair": 0.35, "step free": 0.35, "accessible": 0.25, "postcode": 0.25,
    },
    "escalation": {
        "speak to a human": 0.70, "speak to someone": 0.60, "talk to an agent": 0.70,
        "real person": 0.65, "live agent": 0.70, "customer service": 0.40,
        "complaint": 0.55, "complain": 0.50, "manager": 0.45, "ombudsman": 0.60,
        "bereavement": 0.65, "passed away": 0.65, "died": 0.60, "deceased": 0.65,
        "power of attorney": 0.60, "not happy": 0.40, "unacceptable": 0.40,
    },
}

# Circumstances that go to a human regardless of how confidently we classified
# the intent. Confidence is not the only reason to escalate -- some topics are
# simply not ours to handle.
SENSITIVE = re.compile(
    r"\b(passed away|died|deceased|bereave\w*|probate|estate of|"
    r"power of attorney|terminally ill|suicid\w*|self.harm|"
    r"domestic (abuse|violence)|coerc\w*|financial abuse|"
    r"ombudsman|legal action|solicitor|sue you|court)\b",
    re.IGNORECASE,
)

# Actions the agent is not permitted to complete in chat under any confidence.
OUT_OF_SCOPE = re.compile(
    r"\b(transfer|send|move|withdraw|wire)\b.{0,25}\b(money|funds|£|\$|gbp|payment)\b"
    r"|\b(close|cancel|terminate)\s+(my|the|this)\s+account\b"
    r"|\b(change|update|amend)\s+(my\s+)?(address|name|date of birth|dob)\b"
    r"|\b(reset|change)\s+(my\s+)?(password|pin|passcode)\b",
    re.IGNORECASE,
)

MIN_CONFIDENCE_FLOOR = 0.15


@dataclass
class IntentResult:
    intent: str
    confidence: float
    scores: dict[str, float] = field(default_factory=dict)
    sensitive: bool = False
    out_of_scope: bool = False
    matched_terms: list[str] = field(default_factory=list)

    @property
    def must_escalate(self) -> bool:
        return self.sensitive or self.out_of_scope


def classify(text: str) -> IntentResult:
    """Score every scenario and return the best, with a calibrated confidence."""
    lowered = " " + re.sub(r"\s+", " ", text.lower().strip()) + " "

    scores: dict[str, float] = {}
    matched: dict[str, list[str]] = {}

    for scenario, signals in SIGNALS.items():
        total = 0.0
        hits: list[str] = []
        for term, weight in signals.items():
            if term in lowered:
                total += weight
                hits.append(term)
        scores[scenario] = round(min(total, 1.0), 3)
        matched[scenario] = hits

    best = max(scores, key=lambda s: scores[s])
    best_score = scores[best]
    ranked = sorted(scores.values(), reverse=True)
    runner_up = ranked[1] if len(ranked) > 1 else 0.0

    # Ambiguity penalty. Two scenarios scoring alike means we matched generic
    # banking vocabulary, not a clear intent, and the raw score overstates how
    # sure we are. Halving the margin-based confidence in that case is what
    # pushes genuinely ambiguous queries below the escalation threshold.
    margin = best_score - runner_up
    if best_score <= 0:
        confidence = 0.0
    else:
        confidence = best_score * (0.55 + 0.45 * min(margin / max(best_score, 1e-6), 1.0))

    sensitive = bool(SENSITIVE.search(text))
    out_of_scope = bool(OUT_OF_SCOPE.search(text))

    if sensitive or out_of_scope:
        # We are confident about *what* they want; we are just not allowed to
        # do it. Route to escalation with high confidence in that routing.
        return IntentResult(
            intent="escalation",
            confidence=0.95,
            scores=scores,
            sensitive=sensitive,
            out_of_scope=out_of_scope,
            matched_terms=matched.get(best, []),
        )

    if confidence < MIN_CONFIDENCE_FLOOR:
        return IntentResult(
            intent="unknown",
            confidence=round(confidence, 3),
            scores=scores,
            matched_terms=[],
        )

    return IntentResult(
        intent=best,
        confidence=round(min(confidence, 1.0), 3),
        scores=scores,
        matched_terms=matched[best],
    )
