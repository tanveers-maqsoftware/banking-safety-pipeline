"""Safe-routing layer for the Copilot Studio retail banking agent.

Public entry point is SafetyPipeline.process(). See pipeline.py for why the
stages run in the order they do -- that ordering is the security design.
"""

from .library import Prompt, PromptLibrary, PromptLibraryError
from .pipeline import (
    ACTION_ANSWER,
    ACTION_ESCALATE,
    ACTION_REFUSE,
    PipelineResult,
    SafetyPipeline,
)

__all__ = [
    "SafetyPipeline",
    "PipelineResult",
    "PromptLibrary",
    "Prompt",
    "PromptLibraryError",
    "ACTION_ANSWER",
    "ACTION_REFUSE",
    "ACTION_ESCALATE",
]
