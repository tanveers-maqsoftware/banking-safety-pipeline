"""The safe-routing pipeline.

STAGE ORDER IS A SECURITY DECISION, not an implementation detail. It is:

  1. LANGUAGE   on raw text.  Masking first would strip the lexical signal the
                detector depends on -- a sentence of <PERSON_1> tokens has no
                detectable language.

  2. INJECTION  on raw text.  Must come before both masking and rewriting:
                  - masking first destroys attack signal (Presidio replaces the
                    jailbreak persona "DAN" with <PERSON_1> and it disappears);
                  - rewriting first launders the attack, normalising the
                    payload into clean phrasing before it is ever inspected.
                If this stage blocks, the pipeline STOPS. No LLM call is made.

  3. PII        Presidio analyse + anonymise. After this line, no raw personal
                data exists anywhere downstream. Everything below operates on
                placeholders only.

  4. REWRITE    on masked text. Safe by construction, because step 3 already
                removed everything sensitive.

  5. INTENT     scores the scenario and produces route_confidence -- the number
                Copilot Studio cannot give us and the topics branch on.

  6. ASSEMBLE   fills the active versioned prompt template.

  7. ROUTE      answer / refuse / escalate.

The pipeline is fail-closed. Any unexpected error escalates to a human rather
than falling through to an answer, because in retail banking the cost of an
unhandled error reaching a customer as a confident reply is much higher than
the cost of a handover.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from . import assembler, injection, intent as intent_mod, language, pii, rewriter
from .library import PromptLibrary

# Actions the Copilot Studio topic branches on.
ACTION_ANSWER = "answer"
ACTION_REFUSE = "refuse"
ACTION_ESCALATE = "escalate"

REFUSAL_MESSAGE = (
    "I can't help with that request. I'm here for questions about your "
    "accounts, payments, loans and branches. If you'd like, I can connect "
    "you to a colleague."
)


@dataclass
class PipelineResult:
    """Everything the connector returns to Copilot Studio."""

    safe: bool
    action: str
    block_reason: str = ""
    escalation_reason: str = ""

    language: str = "en"
    language_confidence: float = 0.0
    language_supported: bool = True

    injection_score: float = 0.0
    injection_rules: list[str] = field(default_factory=list)
    injection_families: list[str] = field(default_factory=list)

    masked_text: str = ""
    entities_found: list[str] = field(default_factory=list)
    entity_count: int = 0
    account_ref: str = "not supplied"

    rewritten_text: str = ""
    expansion: list[str] = field(default_factory=list)
    rewrites_applied: list[str] = field(default_factory=list)

    intent: str = "unknown"
    route_confidence: float = 0.0
    intent_scores: dict[str, float] = field(default_factory=dict)

    prompt_id: str = ""
    prompt_version: str = ""
    assembled_prompt: str = ""
    system_prompt: str = ""
    user_prompt: str = ""

    customer_message: str = ""
    stages_run: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SafetyPipeline:
    """Orchestrates the ordered stages. Construct once; it caches heavy models."""

    def __init__(self, library: PromptLibrary | None = None):
        self.library = library or PromptLibrary()

    def process(
        self,
        text: str,
        session_id: str = "default",
        previous_query: str | None = None,
    ) -> PipelineResult:
        try:
            return self._process(text, session_id, previous_query)
        except Exception as exc:  # noqa: BLE001 - fail closed, deliberately
            # An unhandled error must never fall through to an answer.
            return PipelineResult(
                safe=False,
                action=ACTION_ESCALATE,
                escalation_reason="pipeline_error",
                block_reason=f"{type(exc).__name__}: {exc}",
                customer_message=(
                    "Something went wrong at my end. Let me put you through to "
                    "a colleague who can help."
                ),
                stages_run=["error"],
            )

    def _process(
        self, text: str, session_id: str, previous_query: str | None
    ) -> PipelineResult:
        result = PipelineResult(safe=True, action=ACTION_ANSWER)
        stages = result.stages_run

        if not text or not text.strip():
            result.safe = True
            result.action = ACTION_ESCALATE
            result.escalation_reason = "empty_input"
            result.customer_message = "I didn't catch that — could you say it again?"
            stages.append("empty_input")
            return result

        # --- 1. language, on RAW text ---------------------------------------
        lang = language.detect(text)
        result.language = lang.code
        result.language_confidence = lang.confidence
        result.language_supported = lang.supported
        stages.append("language")

        # --- 2. injection, on RAW text --------------------------------------
        verdict = injection.scan(text)
        result.injection_score = verdict.score
        result.injection_rules = verdict.matched_rules
        result.injection_families = sorted(set(verdict.families))
        stages.append("injection")

        if verdict.blocked:
            # Stop here. Nothing is masked, nothing is assembled, and no model
            # is called -- the cheapest and safest possible outcome.
            result.safe = False
            result.action = ACTION_REFUSE
            result.block_reason = f"prompt_injection: {verdict.reason}"
            result.customer_message = REFUSAL_MESSAGE
            stages.append("blocked")
            return result

        # --- 3. PII masking --------------------------------------------------
        masked = pii.mask(text, session_id=session_id, language=lang.code)
        result.masked_text = masked.masked_text
        result.entities_found = masked.entity_types
        result.entity_count = len(masked.entities)
        result.account_ref = masked.account_ref
        stages.append("pii")

        # --- 4. rewrite, on MASKED text only ---------------------------------
        rewritten = rewriter.rewrite(masked.masked_text, previous_query=previous_query)
        result.rewritten_text = rewritten.rewritten
        result.expansion = rewritten.expansion
        result.rewrites_applied = rewritten.applied
        stages.append("rewrite")

        # --- 5. intent + confidence ------------------------------------------
        classified = intent_mod.classify(rewritten.rewritten)
        result.intent = classified.intent
        result.route_confidence = classified.confidence
        result.intent_scores = classified.scores
        stages.append("intent")

        # --- 6/7. route, then assemble the prompt for the chosen route -------
        scenario, escalation_reason = self._route(
            classified, lang, rewritten, verdict
        )
        result.escalation_reason = escalation_reason

        if escalation_reason:
            result.action = ACTION_ESCALATE
            scenario = "escalation"
        stages.append("route")

        prompt = self.library.get(scenario)
        assembled = assembler.build(
            prompt,
            {
                "intent": classified.intent,
                "masked_query": rewritten.rewritten,
                "expansion": rewritten.expansion,
                "language": lang.code,
                "masked_account_ref": masked.account_ref,
                "escalation_reason": escalation_reason or "none",
                "route_confidence": classified.confidence,
            },
        )
        result.prompt_id = assembled.prompt_id
        result.prompt_version = assembled.prompt_version
        result.system_prompt = assembled.system
        result.user_prompt = assembled.user
        result.assembled_prompt = assembled.full_text
        stages.append("assemble")

        if verdict.suspicious and result.action == ACTION_ANSWER:
            # Allowed through, but recorded. These are the cases an analyst
            # reviews to decide whether a rule needs tightening.
            result.block_reason = f"flagged_not_blocked: {verdict.reason}"

        return result

    def _route(
        self,
        classified: intent_mod.IntentResult,
        lang: language.LanguageResult,
        rewritten: rewriter.RewriteResult,
        verdict: injection.InjectionVerdict,
    ) -> tuple[str, str]:
        """Decide the scenario and whether to escalate. Returns (scenario, reason)."""
        # Sensitive circumstances and out-of-scope actions go to a human no
        # matter how confidently we classified them.
        if classified.sensitive:
            return "escalation", "sensitive_circumstance"
        if classified.out_of_scope:
            return "escalation", "out_of_scope_action"

        if lang.needs_escalation:
            return "escalation", "unsupported_language"

        if classified.intent == "unknown":
            return "escalation", "unrecognised_intent"

        # A query that depends on context we do not have would be answered with
        # a guess. Hand it over instead.
        if rewritten.needs_context:
            return "escalation", "missing_context"

        prompt = self.library.get(classified.intent)
        if classified.confidence < prompt.route_confidence_threshold:
            return "escalation", "low_confidence"

        return classified.intent, ""
