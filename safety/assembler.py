"""Context-aware prompt assembly.

Takes the outputs of the earlier pipeline stages and fills the active prompt
template from the versioned library.

The slot-filling is strict on purpose. A missing slot becomes the literal
string "not supplied" rather than an empty gap or a KeyError, because a
half-rendered prompt reaching a model is a silent correctness failure -- the
model fills the gap with a plausible guess, and nobody notices until a customer
is told a balance that does not exist.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .library import Prompt

# Value used when a template slot has nothing to put in it.
NOT_SUPPLIED = "not supplied"


@dataclass
class AssembledPrompt:
    prompt_id: str
    prompt_version: str
    system: str
    user: str
    few_shot: list[dict] = field(default_factory=list)
    slots_used: dict[str, str] = field(default_factory=dict)
    slots_missing: list[str] = field(default_factory=list)

    @property
    def full_text(self) -> str:
        """Everything that would be sent to a model, as one string.

        The test suite scans this for raw PII, so it must include every part
        that leaves the process -- system, few-shot examples and user turn.
        """
        parts = [self.system]
        for example in self.few_shot:
            parts.append(example.get("user", ""))
            parts.append(example.get("assistant", ""))
        parts.append(self.user)
        return "\n\n".join(p for p in parts if p)


def build(prompt: Prompt, slots: dict[str, object]) -> AssembledPrompt:
    """Render a prompt template against the supplied slots."""
    resolved: dict[str, str] = {}
    missing: list[str] = []

    for key in _template_slots(prompt.user_template):
        value = slots.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            resolved[key] = NOT_SUPPLIED
            if key in prompt.required_slots:
                missing.append(key)
        elif isinstance(value, (list, tuple)):
            resolved[key] = ", ".join(str(v) for v in value) or NOT_SUPPLIED
        elif isinstance(value, float):
            resolved[key] = f"{value:.2f}"
        else:
            resolved[key] = str(value)

    return AssembledPrompt(
        prompt_id=prompt.id,
        prompt_version=prompt.version,
        system=prompt.system,
        user=prompt.user_template.format(**resolved),
        few_shot=prompt.few_shot,
        slots_used=resolved,
        slots_missing=missing,
    )


def _template_slots(template: str) -> set[str]:
    import string

    return {f for _, f, _, _ in string.Formatter().parse(template) if f}
