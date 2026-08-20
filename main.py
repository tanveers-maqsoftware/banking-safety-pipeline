"""HTTP service wrapping the safety pipeline, for Copilot Studio to call.

This is a thin transport layer. All decisions live in safety/pipeline.py; this
module only turns an HTTP request into a `SafetyPipeline.process()` call and the
`PipelineResult` back into JSON.

Two things here are deliberate and worth stating.

1. THE SERVICE NEVER RETURNS 5xx FOR A PIPELINE FAILURE. The pipeline is
   fail-closed: an unexpected error already comes back as action="escalate"
   with a customer-safe message. Translating that into an HTTP error would
   destroy the design, because Copilot Studio cannot branch on a 500 -- it just
   shows the customer a connector error. So a processed message is always 200
   with an `action` the topic can route on. Only a malformed request body is a
   4xx, and that is a caller bug rather than a customer outcome.

2. THE RESPONSE SCHEMA IS FLAT. Copilot Studio's connector designer binds
   nested objects poorly; a flat body means every field is directly available
   as a topic variable.

The prompt library is constructed at import time on purpose. If the registry
and the prompt files on disk disagree, the process must refuse to start rather
than serve traffic from an unverified prompt.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel, Field

from safety import SafetyPipeline

pipeline = SafetyPipeline()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Warm the heavy models before the first request arrives.

    Presidio's spaCy pipeline and lingua's language models load lazily behind
    an lru_cache, which would otherwise put several seconds of one-off cost on
    whichever customer happened to be first -- long enough to trip the Copilot
    Studio connector timeout and surface as a failure to that customer.
    """
    pipeline.process("warm up the models", session_id="__warmup__")
    yield


app = FastAPI(
    title="Retail Banking Safety Pipeline",
    description="Safe-routing layer for the Copilot Studio banking agent.",
    version="1.0.0",
    lifespan=lifespan,
)


class ProcessRequest(BaseModel):
    message: str = Field(description="The customer's raw, unmodified message.")
    session_id: str = Field(
        default="default",
        description=(
            "Conversation id. Scopes the PII vault, so placeholders resolve "
            "within one conversation and never across customers."
        ),
    )
    previous_query: str | None = Field(
        default=None,
        description="The previous customer turn, used to resolve 'that one too'.",
    )


class EntityResponse(BaseModel):
    """One PII entity detected and replaced by the masking stage."""

    entity_type: str
    start: int
    end: int
    score: float
    placeholder: str


class ProcessResponse(BaseModel):
    """Flat result. Field groups match how a Copilot Studio topic consumes them."""

    # --- route on these -----------------------------------------------------
    action: str = Field(description="answer | refuse | escalate.")
    safe: bool
    intent: str
    route_confidence: float = Field(
        description="Confidence in the routing decision. Copilot Studio does "
        "not expose its own intent confidence, so topics branch on this."
    )
    escalation_reason: str
    customer_message: str = Field(
        description="Wording to show the customer when refusing or escalating. "
        "Empty when action is 'answer'."
    )

    # --- send these to the model when action == "answer" --------------------
    prompt_ref: str = Field(description="Prompt identity, e.g. balance_inquiry@2.0.0.")
    system_prompt: str
    user_prompt: str

    # --- observability, for logging and the review queue --------------------
    language: str
    masked_text: str = Field(description="Customer text with PII replaced.")
    entities_found: list[EntityResponse]
    entity_count: int
    account_ref: str = Field(description="Safe reference, e.g. 'ending 4321'.")
    injection_score: float
    injection_rules: list[str]
    block_reason: str
    stages_run: list[str]


@app.post("/v1/process", response_model=ProcessResponse)
def process(request: ProcessRequest) -> ProcessResponse:
    """Run one customer message through every safety stage."""
    result = pipeline.process(
        request.message,
        session_id=request.session_id,
        previous_query=request.previous_query,
    )

    return ProcessResponse(
        action=result.action,
        safe=result.safe,
        intent=result.intent,
        route_confidence=result.route_confidence,
        escalation_reason=result.escalation_reason,
        customer_message=result.customer_message,
        prompt_ref=(
            f"{result.prompt_id}@{result.prompt_version}" if result.prompt_id else ""
        ),
        system_prompt=result.system_prompt,
        user_prompt=result.user_prompt,
        language=result.language,
        masked_text=result.masked_text,
        entities_found=[
            EntityResponse(
                entity_type=entity.entity_type,
                start=entity.start,
                end=entity.end,
                score=entity.score,
                placeholder=entity.placeholder,
            )
            for entity in result.entities_found
        ],
        entity_count=result.entity_count,
        account_ref=result.account_ref,
        injection_score=result.injection_score,
        injection_rules=result.injection_rules,
        block_reason=result.block_reason,
        stages_run=result.stages_run,
    )


@app.get("/v1/health")
def health() -> dict:
    """Liveness check that also reports which prompt versions are being served."""
    return {"status": "ok", "active_prompts": pipeline.library.active_map()}
