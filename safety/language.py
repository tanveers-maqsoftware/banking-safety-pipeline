"""Language detection.

Uses `lingua` rather than `langdetect` because banking chat utterances are
short and terse ("balance?", "od charge", "atm near me"), and langdetect's
n-gram approach is unreliable below about 20 characters -- it will happily
report Somali for "balance pls". Lingua is built for exactly this case and
reports a confidence we can route on.

The candidate language set is restricted to languages a UK retail bank
realistically serves. A restricted set materially improves accuracy on short
text, because the detector is not distributing probability mass across 75
languages most of which will never appear.

Detection runs on RAW text, before masking: replacing words with
<PERSON_1> tokens would strip out exactly the lexical signal the detector uses.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

# Languages the agent can serve directly. Anything else is a valid escalation
# reason rather than a failure -- a human colleague or interpreter takes over.
SUPPORTED = {"en"}

# Additional languages we can at least *identify*, so the handover note can say
# which language the customer needs. Chosen to reflect the most commonly spoken
# non-English languages in the UK.
DETECTABLE = ["en", "pl", "ur", "pa", "bn", "gu", "ar", "fr", "es", "de", "pt", "it", "ro", "zh"]

# Below this confidence we do not trust the verdict and assume English rather
# than escalating a UK customer over a two-word message.
MIN_CONFIDENCE = 0.55

# Short inputs are inherently unreliable to classify. Under this length we
# require a much stronger signal before declaring a non-English language.
SHORT_TEXT_CHARS = 12
SHORT_TEXT_CONFIDENCE = 0.90


@dataclass
class LanguageResult:
    code: str
    confidence: float
    supported: bool
    reliable: bool

    @property
    def needs_escalation(self) -> bool:
        """A confidently-detected unsupported language should reach a human."""
        return self.reliable and not self.supported


@lru_cache(maxsize=1)
def _detector():
    from lingua import LanguageDetectorBuilder, IsoCode639_1

    codes = [getattr(IsoCode639_1, c.upper()) for c in DETECTABLE]
    return (
        LanguageDetectorBuilder.from_iso_codes_639_1(*codes)
        .with_preloaded_language_models()
        .build()
    )


def detect(text: str) -> LanguageResult:
    """Detect the language of raw user text."""
    stripped = text.strip()
    if len(stripped) < 3:
        return LanguageResult("en", 0.0, True, False)

    detector = _detector()
    values = detector.compute_language_confidence_values(stripped)
    if not values:
        return LanguageResult("en", 0.0, True, False)

    best = values[0]
    code = best.language.iso_code_639_1.name.lower()
    confidence = float(best.value)

    threshold = (
        SHORT_TEXT_CONFIDENCE if len(stripped) < SHORT_TEXT_CHARS else MIN_CONFIDENCE
    )
    reliable = confidence >= threshold

    # Unreliable detection defaults to English rather than guessing, so a
    # terse UK customer is never bounced to an interpreter queue.
    if not reliable:
        return LanguageResult("en", round(confidence, 3), True, False)

    return LanguageResult(code, round(confidence, 3), code in SUPPORTED, True)
