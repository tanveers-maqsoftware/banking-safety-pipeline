"""Query rewriting and expansion.

Runs on MASKED text only -- after Presidio -- so nothing sensitive is ever
handled here, and after the injection scan, so this never launders an attack
into cleaner phrasing.

Everything in this module is deterministic. No LLM call. That is a deliberate
constraint: a rewriter that calls a model is (a) another injection surface,
because the attacker's text becomes a prompt, and (b) untestable, because the
same input can produce different output run to run. Rule-based rewriting is
boring, auditable, and unit-testable, which is what a safety path needs.

Three jobs:
  1. Normalise banking shorthand   "od chrg on my a/c" -> "overdraft charge on my account"
  2. Resolve context               "and that one too"  -> uses the prior turn's intent
  3. Expand for retrieval          "balance" -> also search "available funds", "cleared balance"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Shorthand and abbreviations customers actually type. Applied with word
# boundaries so "od" does not rewrite the middle of "odd" or "method".
SHORTHAND: dict[str, str] = {
    r"a/c": "account",
    r"acc": "account",
    r"acct": "account",
    r"accs": "accounts",
    r"bal": "balance",
    r"od": "overdraft",
    r"o/d": "overdraft",
    r"dd": "direct debit",
    r"so": "standing order",
    r"sc": "sort code",
    r"cc": "credit card",
    r"dc": "debit card",
    r"atm": "cash machine",
    r"txn": "transaction",
    r"trans": "transaction",
    r"tx": "transaction",
    r"stmt": "statement",
    r"pmt": "payment",
    r"pymt": "payment",
    r"mtg": "mortgage",
    r"isa": "individual savings account",
    r"apr": "annual percentage rate",
    r"otp": "one time passcode",
    r"ni": "national insurance",
    r"dob": "date of birth",
    r"pls": "please",
    r"plz": "please",
    r"thx": "thanks",
    r"asap": "as soon as possible",
    r"idk": "i do not know",
    r"cant": "cannot",
    r"wont": "will not",
    r"dont": "do not",
    r"whats": "what is",
    r"hows": "how is",
    r"im": "i am",
    r"ive": "i have",
    r"u": "you",
    r"ur": "your",
    r"r": "are",
    r"n": "and",
    r"y": "why",
}

# Terms added to the query to widen knowledge-source retrieval. These are not
# substitutions -- the original wording is preserved and these ride alongside.
EXPANSIONS: dict[str, list[str]] = {
    "balance": ["available balance", "cleared funds", "current balance", "how much money"],
    "overdraft": ["overdraft limit", "overdraft fee", "unarranged overdraft", "arranged overdraft"],
    "transaction": ["payment", "transfer", "debit", "credit", "statement entry"],
    "direct debit": ["recurring payment", "standing order", "scheduled payment", "mandate"],
    "standing order": ["recurring payment", "direct debit", "scheduled payment"],
    "loan": ["personal loan", "borrowing", "lending", "application", "repayment"],
    "mortgage": ["home loan", "remortgage", "fixed rate", "repayment", "application"],
    "dispute": ["chargeback", "unrecognised transaction", "fraud claim", "refund", "unauthorised"],
    "fraud": ["scam", "unauthorised transaction", "card misuse", "chargeback"],
    "branch": ["local branch", "opening hours", "in person", "counter service"],
    "cash machine": ["atm", "cashpoint", "withdrawal", "cash withdrawal"],
    "card": ["debit card", "credit card", "replacement card", "card activation"],
    "statement": ["transaction history", "monthly statement", "account activity"],
    "interest": ["interest rate", "apr", "aer", "annual percentage rate"],
    "fee": ["charge", "cost", "penalty", "commission"],
    "refund": ["reimbursement", "money back", "chargeback", "credit"],
    "password": ["passcode", "login", "credentials", "sign in"],
    "close": ["closure", "cancel", "terminate", "end account"],
    "complaint": ["escalate", "unhappy", "dissatisfied", "ombudsman"],
}

# Vague references that only make sense against the prior turn.
_ANAPHORA = re.compile(
    r"\b(that one|this one|it|the same|that|those|them|the above|as before|"
    r"the thing i mentioned|like i said|same as last time)\b",
    re.IGNORECASE,
)

# Placeholder tokens from the masking stage must survive rewriting untouched.
_PLACEHOLDER = re.compile(r"<[A-Z_]+_\d+>")


@dataclass
class RewriteResult:
    original: str
    rewritten: str
    expansion: list[str] = field(default_factory=list)
    applied: list[str] = field(default_factory=list)
    needs_context: bool = False

    @property
    def expansion_str(self) -> str:
        return ", ".join(self.expansion)


def _protect_placeholders(text: str) -> tuple[str, dict[str, str]]:
    """Swap placeholders for inert sentinels so rewriting cannot corrupt them.

    Without this, "<UK_NINO_1>" would have its "NI" rewritten to
    "national insurance" and the token would no longer resolve in the vault.
    """
    saved: dict[str, str] = {}
    def _sub(match: re.Match) -> str:
        key = f"\x00{len(saved)}\x00"
        saved[key] = match.group(0)
        return key
    return _PLACEHOLDER.sub(_sub, text), saved


def _restore_placeholders(text: str, saved: dict[str, str]) -> str:
    for key, value in saved.items():
        text = text.replace(key, value)
    return text


def expand_shorthand(text: str) -> tuple[str, list[str]]:
    """Expand banking abbreviations, leaving placeholders intact."""
    protected, saved = _protect_placeholders(text)
    applied: list[str] = []

    for short, long in sorted(SHORTHAND.items(), key=lambda kv: -len(kv[0])):
        pattern = re.compile(rf"(?<![\w/]){re.escape(short)}(?![\w/])", re.IGNORECASE)
        if pattern.search(protected):
            protected = pattern.sub(long, protected)
            applied.append(f"{short}->{long}")

    protected = re.sub(r"\s{2,}", " ", protected).strip()
    return _restore_placeholders(protected, saved), applied


def build_expansion(text: str, intent: str | None = None) -> list[str]:
    """Collect related retrieval terms for the concepts present in the query."""
    lowered = text.lower()
    terms: list[str] = []
    for concept, related in EXPANSIONS.items():
        if concept in lowered:
            terms.extend(t for t in related if t not in terms and t not in lowered)
    return terms[:8]


def needs_context(text: str) -> bool:
    """True when the query leans on something said in a previous turn."""
    stripped = _PLACEHOLDER.sub("", text).strip()
    if not stripped:
        return False
    # A very short query made entirely of anaphora is context-dependent.
    if len(stripped.split()) <= 3 and _ANAPHORA.search(stripped):
        return True
    # Otherwise require an anaphor with no concrete banking noun to anchor it.
    has_anchor = any(concept in stripped.lower() for concept in EXPANSIONS)
    return bool(_ANAPHORA.search(stripped)) and not has_anchor


def rewrite(
    text: str, previous_query: str | None = None, intent: str | None = None
) -> RewriteResult:
    """Rewrite and expand a masked query.

    `previous_query` supplies the prior turn so that context-dependent phrasing
    can be anchored. When a query needs context and none is available, that is
    reported rather than guessed -- the pipeline turns it into an escalation,
    which is the honest outcome.
    """
    rewritten, applied = expand_shorthand(text)
    context_needed = needs_context(rewritten)

    if context_needed and previous_query:
        anchor, _ = expand_shorthand(previous_query)
        rewritten = f"{rewritten} (referring to: {anchor})"
        applied.append("context:anchored-to-previous-turn")
        context_needed = False

    expansion = build_expansion(rewritten, intent)
    if previous_query:
        for term in build_expansion(previous_query, intent):
            if term not in expansion and len(expansion) < 8:
                expansion.append(term)

    return RewriteResult(
        original=text,
        rewritten=rewritten,
        expansion=expansion,
        applied=applied,
        needs_context=context_needed,
    )
