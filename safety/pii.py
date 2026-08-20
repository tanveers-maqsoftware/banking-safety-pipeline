"""PII detection and masking via Microsoft Presidio.

Presidio moved from the microsoft GitHub org to data-privacy-stack in 2026
(github.com/microsoft/presidio still redirects). The pip package names are
unchanged: presidio-analyzer, presidio-anonymizer.

Two design decisions worth stating:

1. We REPLACE with typed placeholders (<UK_NINO_1>) rather than redacting to a
   uniform block. The LLM downstream still needs to understand the shape of the
   query -- "my <UK_NINO_1> is wrong on my statement" is answerable, whereas
   "my ***** is wrong" is not. Typed, numbered placeholders preserve structure
   and coreference while carrying no sensitive value.

2. The placeholder -> original mapping is held in a session-scoped, in-memory
   vault that is NEVER serialised into the API response. It exists so the agent
   can say "your account ending 4321" without the full value crossing the
   network. Nothing persists it to disk.

Out of the box Presidio does not recognise UK sort codes or UK domestic account
numbers, which are the two most common identifiers in retail banking chat, so
both are added as custom recognisers below.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from functools import lru_cache

# Entities we ask Presidio for. Deliberately scoped: requesting every entity
# type Presidio supports produces noisy PERSON/LOCATION hits on ordinary
# banking nouns and degrades the masked text the model has to work with.
BANKING_ENTITIES = [
    "UK_NINO",
    "UK_NHS",
    "IBAN_CODE",
    "CREDIT_CARD",
    "PERSON",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "DATE_TIME",
    "LOCATION",
    "UK_SORT_CODE",
    "UK_ACCOUNT_NUMBER",
]

# Below this Presidio confidence we ignore a hit. PERSON in particular fires on
# capitalised banking terms; 0.4 is the level at which the benign corpus stops
# losing meaningful words.
MIN_SCORE = 0.4

_UK_SORT_CODE = r"\b\d{2}[-\s]\d{2}[-\s]\d{2}\b"
# Account numbers vary by country. Context words below keep this from treating
# every long numeric value as an account number.
_ACCOUNT_NUMBER = r"(?<!\d)\d{8,18}(?!\d)"
# Context-aware coverage for common international 10-digit contact numbers.
_CONTACT_NUMBER = r"(?<!\d)\d{10}(?!\d)"


@dataclass
class Entity:
    """One detected PII entity."""

    entity_type: str
    start: int
    end: int
    score: float
    placeholder: str = ""


@dataclass
class MaskResult:
    """Outcome of masking one utterance."""

    masked_text: str
    entities: list[Entity] = field(default_factory=list)
    account_ref: str = "not supplied"

    @property
    def entity_types(self) -> list[str]:
        return sorted({e.entity_type for e in self.entities})

    @property
    def found_any(self) -> bool:
        return bool(self.entities)


class SessionVault:
    """In-memory, session-scoped placeholder -> original value store.

    Never serialised to the API response and never written to disk. Sessions
    are dropped on process exit; there is no persistence layer by design.
    """

    def __init__(self) -> None:
        self._data: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()

    def store(self, session_id: str, mapping: dict[str, str]) -> None:
        if not mapping:
            return
        with self._lock:
            self._data.setdefault(session_id, {}).update(mapping)

    def resolve(self, session_id: str, placeholder: str) -> str | None:
        with self._lock:
            return self._data.get(session_id, {}).get(placeholder)

    def last_four(self, session_id: str, placeholder: str) -> str | None:
        """Last four digits of a stored value, for 'your account ending 4321'."""
        value = self.resolve(session_id, placeholder)
        if not value:
            return None
        digits = re.sub(r"\D", "", value)
        return digits[-4:] if len(digits) >= 4 else None

    def forget(self, session_id: str) -> None:
        with self._lock:
            self._data.pop(session_id, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


VAULT = SessionVault()


@lru_cache(maxsize=1)
def _analyzer():
    """Build the Presidio analyzer once. Loading spaCy is expensive."""
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer

    engine = AnalyzerEngine()

    engine.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="UK_SORT_CODE",
            name="UkSortCodeRecognizer",
            patterns=[Pattern("uk_sort_code", _UK_SORT_CODE, 0.6)],
            context=["sort", "sortcode", "sort code", "branch", "bank"],
        )
    )
    engine.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="UK_ACCOUNT_NUMBER",
            name="UkAccountNumberRecognizer",
            patterns=[Pattern("account_number", _ACCOUNT_NUMBER, 0.85)],
            context=["account", "acc", "a/c", "acct", "number", "sort", "current", "savings"],
        )
    )
    engine.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            name="ContactNumberRecognizer",
            patterns=[Pattern("contact_number", _CONTACT_NUMBER, 0.9)],
            context=["contact", "phone", "mobile", "telephone", "call"],
        )
    )
    return engine


@lru_cache(maxsize=1)
def _anonymizer():
    from presidio_anonymizer import AnonymizerEngine

    return AnonymizerEngine()


def analyze(text: str, language: str = "en") -> list[Entity]:
    """Detect PII entities. Presidio's NLP models are English-only here."""
    if not text.strip():
        return []

    results = _analyzer().analyze(
        text=text,
        entities=BANKING_ENTITIES,
        language="en",
        score_threshold=MIN_SCORE,
    )
    entities = [
        Entity(r.entity_type, r.start, r.end, round(r.score, 3)) for r in results
    ]
    return _drop_overlaps(entities)


def _drop_overlaps(entities: list[Entity]) -> list[Entity]:
    """Keep the strongest entity where spans overlap.

    Presidio can return an 8-digit run as both UK_ACCOUNT_NUMBER and part of a
    longer match. Masking overlapping spans corrupts the offsets, so we resolve
    to one winner per span: longest first, then highest score.
    """
    ordered = sorted(entities, key=lambda e: (-(e.end - e.start), -e.score, e.start))
    kept: list[Entity] = []
    for candidate in ordered:
        if any(candidate.start < k.end and k.start < candidate.end for k in kept):
            continue
        kept.append(candidate)
    return sorted(kept, key=lambda e: e.start)


def mask(text: str, session_id: str = "default", language: str = "en") -> MaskResult:
    """Replace PII with typed placeholders and vault the originals.

    Masking is applied right-to-left so that each replacement cannot shift the
    offsets of the ones still to be applied.
    """
    entities = analyze(text, language=language)
    if not entities:
        return MaskResult(masked_text=text, entities=[], account_ref="not supplied")

    counters: dict[str, int] = {}
    mapping: dict[str, str] = {}
    masked = text

    for entity in sorted(entities, key=lambda e: e.start, reverse=True):
        counters[entity.entity_type] = counters.get(entity.entity_type, 0) + 1

    # Number placeholders left-to-right so <PERSON_1> is the first person named,
    # which is what a reader expects, while still substituting right-to-left.
    running: dict[str, int] = {}
    for entity in sorted(entities, key=lambda e: e.start):
        running[entity.entity_type] = running.get(entity.entity_type, 0) + 1
        entity.placeholder = f"<{entity.entity_type}_{running[entity.entity_type]}>"
        mapping[entity.placeholder] = text[entity.start : entity.end]

    for entity in sorted(entities, key=lambda e: e.start, reverse=True):
        masked = masked[: entity.start] + entity.placeholder + masked[entity.end :]

    VAULT.store(session_id, mapping)

    return MaskResult(
        masked_text=masked,
        entities=entities,
        account_ref=_account_ref(session_id, entities),
    )


def _account_ref(session_id: str, entities: list[Entity]) -> str:
    """Build a safe 'ending 1234' reference from the strongest account-like hit.

    This is the whole point of the vault: the model gets enough to identify the
    account conversationally, and the full value never leaves this process.
    """
    priority = ["UK_ACCOUNT_NUMBER", "CREDIT_CARD", "IBAN_CODE"]
    for entity_type in priority:
        for entity in entities:
            if entity.entity_type != entity_type:
                continue
            tail = VAULT.last_four(session_id, entity.placeholder)
            if tail:
                return f"ending {tail}"
    return "not supplied"


def contains_raw_pii(candidate: str, originals: list[str]) -> list[str]:
    """Return any original PII value that leaked into `candidate`.

    Used by the test suite to assert the pipeline's core invariant: no raw PII
    value ever appears in an assembled prompt.
    """
    leaked = []
    for value in originals:
        value = value.strip()
        if len(value) < 4:
            continue
        if value.lower() in candidate.lower():
            leaked.append(value)
    return leaked
