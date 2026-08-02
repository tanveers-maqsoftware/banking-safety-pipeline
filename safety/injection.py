"""Prompt injection and jailbreak detection.

Runs on RAW user text, before masking and before rewriting. Order matters:

  * Masking first would destroy signal. Presidio would replace "DAN" (a common
    jailbreak persona) with <PERSON_1> and the attack would vanish from view.
  * Rewriting first would launder the attack. The rewriter normalises shorthand
    into clean banking phrasing, which is exactly what an attacker wants applied
    to their payload before it reaches a detector.

The scanner returns an explainable verdict -- score plus the rules that fired --
rather than a boolean, because a support agent that blocks a customer needs to
be able to say which rule it was, and an analyst needs to tune it.

Detection is layered:
  1. Normalise, to strip evasion (zero-width chars, homoglyphs, base64, leet).
  2. Match rule families against BOTH raw and normalised text.
  3. Sum weights, compare to threshold.

A note on precision. Retail banking customers legitimately write things like
"ignore the pending transaction" and "my system password". Blocking those is a
worse failure than missing a marginal attack, because it happens far more often
and to real customers. Several rules below are therefore narrowed with negative
lookaheads and banking-context exclusions, and the benign corpus in
tests/corpora/injection.json exists to hold that line under change.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# Score at or above which we refuse outright.
BLOCK_THRESHOLD = 0.75
# Score at or above which we allow through but flag for review.
SUSPICIOUS_THRESHOLD = 0.40

# Characters used to break tokenisation or hide payloads. Zero-width joiners,
# bidi overrides and soft hyphens all render as nothing but survive copy-paste.
_INVISIBLE = dict.fromkeys(
    [
        0x00AD, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B,
        0x202C, 0x202D, 0x202E, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
        0xFEFF,
    ]
)

# Cyrillic/Greek lookalikes swapped for Latin so "іgnore" (Cyrillic і) matches.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ν": "v", "ο": "o", "α": "a",
        "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "ϲ": "c", "ѵ": "v",
    }
)

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


@dataclass
class Rule:
    """One detection rule."""

    id: str
    family: str
    pattern: re.Pattern
    weight: float
    description: str


@dataclass
class InjectionVerdict:
    """Explainable result of a scan."""

    blocked: bool
    suspicious: bool
    score: float
    matched_rules: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    normalised_text: str = ""
    decoded_segments: list[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        """Short human-readable reason, for the refusal message and the queue."""
        if not self.matched_rules:
            return ""
        return f"{', '.join(sorted(set(self.families)))} ({len(self.matched_rules)} rule(s))"


def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# --- Rule families -----------------------------------------------------------
#
# Weights are calibrated so that one strong rule blocks on its own, while two
# weak signals must co-occur. They were tuned against the corpus in
# tests/corpora/injection.json; changing one means re-running
# tools/redteam_report.py.

RULES: list[Rule] = [
    # --- instruction override ------------------------------------------------
    Rule(
        "R-001", "instruction_override",
        # "the above"/"previous" + instruction noun. Narrow enough that
        # "ignore the pending transaction" does not match.
        _rx(r"\b(ignore|disregard|forget|discard|override)\b[^.!?\n]{0,40}?"
            r"\b(previous|prior|above|earlier|initial|original|all)\b"
            r"[^.!?\n]{0,20}?\b(instruction|prompt|rule|direction|command|guideline|context|message)s?\b"),
        0.85,
        "Asks the model to discard its prior instructions.",
    ),
    Rule(
        "R-002", "instruction_override",
        _rx(r"\b(new|updated|revised|real|actual|true)\s+(instruction|rule|directive|system\s+prompt)s?\s*[:\-]"),
        0.80,
        "Presents replacement instructions as authoritative.",
    ),
    Rule(
        "R-003", "instruction_override",
        _rx(r"\bfrom\s+now\s+on\b[^.!?\n]{0,60}?\b(you|your)\b[^.!?\n]{0,40}?"
            r"\b(will|must|are|should|shall)\b"),
        0.55,
        "Attempts to install a persistent behavioural override.",
    ),
    Rule(
        "R-004", "instruction_override",
        _rx(r"\b(stop|cease)\s+(being|acting\s+as|behaving\s+as)\b"),
        0.60,
        "Asks the model to abandon its assigned role.",
    ),
    Rule(
        "R-005", "instruction_override",
        _rx(r"\b(your\s+)?(previous|prior|earlier|original)\s+(instruction|prompt|rule)s?\s+"
            r"(are|is|were|was)\s+(no\s+longer|not|void|invalid|cancelled|canceled|obsolete)"),
        0.85,
        "Asserts that prior instructions have been revoked.",
    ),

    # --- role-play / persona hijack -----------------------------------------
    Rule(
        "R-010", "role_play",
        _rx(r"\b(you\s+are\s+now|you're\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as|"
            r"role-play\s+as|simulate\s+being|imagine\s+you\s+are|behave\s+like)\b"
            # Exclude the legitimate banking sense: "act as guarantor",
            # "act as a signatory", "act as power of attorney".
            r"(?![^.!?\n]{0,15}\b(guarantor|signatory|trustee|executor|attorney|"
            r"joint\s+account|beneficiary|nominee)\b)"),
        0.75,
        "Attempts to reassign the model's persona.",
    ),
    Rule(
        "R-011", "role_play",
        _rx(r"\b(DAN|AIM|STAN|DUDE|jailbreak|jail\s?break)\b"),
        0.80,
        "Names a known jailbreak persona or technique.",
    ),
    Rule(
        "R-012", "role_play",
        _rx(r"\b(developer|debug|god|admin|maintenance|unrestricted|unfiltered|sudo)\s+mode\b"),
        0.85,
        "Invokes a fictitious privileged mode.",
    ),
    Rule(
        "R-013", "role_play",
        _rx(r"\b(without|no)\s+(any\s+)?(restriction|filter|censorship|limitation|guardrail|rule)s?\b"),
        0.70,
        "Requests operation without safety constraints.",
    ),
    Rule(
        "R-014", "role_play",
        _rx(r"\b(you\s+have\s+no|you\s+don'?t\s+have\s+any)\s+"
            r"(restriction|rule|guideline|filter|limitation)s?\b"),
        0.80,
        "Asserts the model has no constraints.",
    ),
    Rule(
        "R-015", "role_play",
        _rx(r"\bhypothetical(ly)?\b[^.!?\n]{0,60}?\b(no|without)\s+(rule|restriction|filter|limit)"),
        0.65,
        "Uses a hypothetical framing to shed constraints.",
    ),

    # --- system prompt exfiltration ------------------------------------------
    Rule(
        "R-020", "exfiltration",
        _rx(r"\b(show|print|reveal|repeat|display|output|tell\s+me|what\s+(is|are)|give\s+me|"
            r"disclose|reproduce)\b[^.!?\n]{0,40}?\b(your\s+)?"
            r"(system\s+prompt|initial\s+prompt|system\s+message|instruction|"
            r"prompt\s+template|configuration|rule\s?set|guideline)s?\b"),
        0.85,
        "Attempts to extract the system prompt or instructions.",
    ),
    Rule(
        "R-021", "exfiltration",
        _rx(r"\b(repeat|print|output|echo|show)\b[^.!?\n]{0,30}?"
            r"\b(everything|all\s+(of\s+)?the\s+text|the\s+text)\b[^.!?\n]{0,20}?"
            r"\b(above|before|preceding|prior)\b"),
        0.85,
        "Attempts to dump preceding context.",
    ),
    Rule(
        "R-022", "exfiltration",
        _rx(r"\b(what|which)\s+(model|llm|version|gpt|ai)\b[^.!?\n]{0,30}?"
            r"\b(are\s+you|do\s+you\s+use|is\s+this|powers?\s+you)\b"),
        0.35,
        "Probes for model identity -- reconnaissance, not an attack alone.",
    ),
    Rule(
        "R-023", "exfiltration",
        _rx(r"\b(list|enumerate|describe)\b[^.!?\n]{0,30}?\b(your\s+)?"
            r"(tool|function|action|capabilit|connector|api)\w*\b[^.!?\n]{0,30}?"
            r"\b(available|you\s+have|access)\b"),
        0.55,
        "Enumerates available tools -- reconnaissance for tool abuse.",
    ),
    Rule(
        "R-024", "exfiltration",
        _rx(r"\b(begin|start)\s+(your\s+)?(reply|response|answer)\s+with\b[^.!?\n]{0,40}?"
            r"\b(you\s+are|system|instruction)\b"),
        0.70,
        "Prefix-injection to coax the system prompt into the reply.",
    ),

    # --- delimiter / role escape ---------------------------------------------
    Rule(
        "R-030", "delimiter_escape",
        _rx(r"<\|?\s*(im_start|im_end|system|endoftext|assistant|user)\s*\|?>"),
        0.90,
        "Injects chat-template control tokens.",
    ),
    Rule(
        "R-031", "delimiter_escape",
        # A role label at the start of a line, i.e. forging a conversation turn.
        _rx(r"(^|\n)\s*(system|assistant|developer)\s*:\s*\S"),
        0.75,
        "Forges a system or assistant conversational turn.",
    ),
    Rule(
        "R-032", "delimiter_escape",
        _rx(r"(\[\s*(system|inst|/inst|assistant)\s*\]|\{\{\s*system\s*\}\})"),
        0.80,
        "Injects bracketed role or instruction delimiters.",
    ),
    Rule(
        "R-033", "delimiter_escape",
        _rx(r"-{3,}\s*(end|stop)\s+of\s+(prompt|instruction|system|context)\s*-{3,}"),
        0.80,
        "Fakes an end-of-prompt boundary.",
    ),

    # --- policy / guardrail subversion ---------------------------------------
    Rule(
        "R-040", "policy_subversion",
        _rx(r"\b(this\s+is\s+(just\s+)?a\s+(test|drill|simulation)|for\s+testing\s+purposes)\b"
            r"[^.!?\n]{0,60}?\b(ignore|bypass|skip|disable|override)\b"),
        0.70,
        "Uses a test framing to justify bypassing controls.",
    ),
    Rule(
        "R-041", "policy_subversion",
        _rx(r"\b(bypass|circumvent|get\s+around|work\s+around|disable|turn\s+off|switch\s+off)\b"
            r"[^.!?\n]{0,30}?\b(security|verification|authentication|safety|filter|check|"
            r"guardrail|moderation|policy|restriction)\w*\b"),
        0.85,
        "Explicitly requests control bypass.",
    ),
    Rule(
        "R-042", "policy_subversion",
        _rx(r"\b(i\s+am|i'm|this\s+is)\s+(the|a|an)\s+"
            r"(developer|administrator|admin|engineer|security\s+researcher|auditor|"
            r"your\s+creator|from\s+(it|security|compliance))\b"),
        0.65,
        "Claims privileged identity to justify an exception.",
    ),
    Rule(
        "R-043", "policy_subversion",
        _rx(r"\b(don'?t|do\s+not|never)\s+(tell|inform|mention\s+to|alert|notify)\s+"
            r"(anyone|the\s+(user|customer|human|team|bank)|management)\b"),
        0.75,
        "Requests concealment from oversight.",
    ),
    Rule(
        "R-044", "policy_subversion",
        # Transfers cannot be done in chat at all, so an instruction-shaped
        # transfer request is an attempt to drive an unauthorised action.
        _rx(r"\b(transfer|send|move|withdraw|wire)\b[^.!?\n]{0,30}?"
            r"(all\s+(the|my|of)\s+)?(fund|money|balance|cash|GBP|£|\$)\w*"
            r"[^.!?\n]{0,40}?\b(to|into)\b[^.!?\n]{0,30}?\b(account|iban|sort\s?code)\b"),
        0.70,
        "Instructs an unauthorised funds movement.",
    ),

    # --- encoding / obfuscation ----------------------------------------------
    Rule(
        "R-050", "encoding",
        _rx(r"\b(decode|base64|rot13|reverse\s+(this|the\s+following)|hex\s?decode|"
            r"from\s+base\s?64)\b[^.!?\n]{0,40}?\b(and|then)\b[^.!?\n]{0,30}?"
            r"\b(execute|follow|obey|do|run|comply)\b"),
        0.85,
        "Asks the model to decode then act on hidden instructions.",
    ),
    Rule(
        "R-051", "encoding",
        _rx(r"\b(respond|reply|answer|translate)\b[^.!?\n]{0,30}?\b(in|using)\b"
            r"[^.!?\n]{0,20}?\b(base64|rot13|hex|morse|binary|leetspeak)\b"),
        0.60,
        "Requests an encoded reply, a common filter-evasion channel.",
    ),
]


def normalise(text: str) -> tuple[str, list[str]]:
    """Strip evasion techniques so rules match the attacker's intent.

    Returns the normalised text and any base64 payloads that decoded to
    plausible instruction text, so those can be rescanned in their own right.
    """
    # NFKC folds fullwidth and other compatibility forms onto ASCII.
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_INVISIBLE)
    text = text.translate(_HOMOGLYPHS)

    decoded: list[str] = []
    for match in _BASE64_RUN.findall(text):
        try:
            raw = base64.b64decode(match + "=" * (-len(match) % 4), validate=True)
            candidate = raw.decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        # Only treat it as a payload if it looks like language, not binary.
        printable = sum(c.isprintable() or c.isspace() for c in candidate)
        if len(candidate) >= 8 and printable / len(candidate) > 0.9:
            decoded.append(candidate)

    if decoded:
        text = text + "\n" + "\n".join(decoded)

    # Collapse spacing tricks: "i g n o r e" and "ignore    previous".
    text = re.sub(r"(?<=\b\w)\s+(?=\w\b)", "", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text, decoded


def _leet_variant(text: str) -> str:
    """Fold digit-substitution, but only in words that are mostly letters.

    Applying leet folding to the whole string would mangle account numbers and
    amounts into words and generate false positives, so it runs per-token and
    only where letters already dominate.
    """
    out = []
    for token in re.split(r"(\s+)", text):
        letters = sum(c.isalpha() for c in token)
        if letters >= 2 and letters >= len(token) / 2:
            out.append(token.translate(_LEET))
        else:
            out.append(token)
    return "".join(out)


def scan(text: str) -> InjectionVerdict:
    """Scan raw user text for injection attempts."""
    if not text or not text.strip():
        return InjectionVerdict(
            blocked=False, suspicious=False, score=0.0, normalised_text=""
        )

    normalised, decoded = normalise(text)
    leet = _leet_variant(normalised)
    haystacks = {text, normalised, leet}

    matched: list[str] = []
    families: list[str] = []
    score = 0.0

    for rule in RULES:
        if any(rule.pattern.search(h) for h in haystacks):
            matched.append(rule.id)
            families.append(rule.family)
            score += rule.weight

    # A decoded base64 payload is itself evidence of evasion, even if the
    # decoded content did not trip a rule on its own.
    if decoded:
        score += 0.25
        matched.append("R-052")
        families.append("encoding")

    score = min(score, 1.0)

    return InjectionVerdict(
        blocked=score >= BLOCK_THRESHOLD,
        suspicious=SUSPICIOUS_THRESHOLD <= score < BLOCK_THRESHOLD,
        score=round(score, 3),
        matched_rules=matched,
        families=families,
        normalised_text=normalised,
        decoded_segments=decoded,
    )


def rule_index() -> dict[str, Rule]:
    """Rule lookup, used by the red-team report to explain each detection."""
    index = {r.id: r for r in RULES}
    index["R-052"] = Rule(
        "R-052", "encoding", _rx(r"(?!x)x"), 0.25,
        "Input contained a decodable base64 payload.",
    )
    return index
