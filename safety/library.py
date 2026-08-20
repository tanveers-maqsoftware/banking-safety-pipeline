"""Versioned prompt library.

The library is a set of JSON files, one per scenario-version, plus a registry
that pins which version is active and records a sha256 of each file.

The hash check is the point of the registry. Without it "versioning" is just a
filename convention -- anyone could edit balance_inquiry.v2.json in place and
the agent's behaviour would change with no version bump and no audit trail.
Recomputing the hash at load time turns that silent edit into a startup failure.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"
REGISTRY_PATH = PROMPTS_DIR / "registry.json"

# Slots the assembler is always able to supply. A template referencing anything
# outside this set is a bug we want to catch at load time, not at request time.
KNOWN_SLOTS = {
    "intent",
    "masked_query",
    "expansion",
    "language",
    "masked_account_ref",
    "escalation_reason",
    "route_confidence",
}


class PromptLibraryError(Exception):
    """Raised when the library on disk does not match the registry."""


@dataclass
class Prompt:
    """One versioned prompt, as loaded from disk."""

    id: str
    version: str
    status: str
    scenario: str
    system: str
    user_template: str
    required_slots: list[str]
    few_shot: list[dict] = field(default_factory=list)
    route_confidence_threshold: float = 0.6
    changelog: list[dict] = field(default_factory=list)
    source_file: str = ""
    sha256: str = ""

    @property
    def ref(self) -> str:
        """Stable identifier for logging, e.g. 'balance_inquiry@2.0.0'."""
        return f"{self.id}@{self.version}"


def sha256_of(path: Path) -> str:
    """Hash a prompt file's bytes.

    Hashing raw bytes rather than parsed JSON is deliberate: a reformat that
    leaves the JSON semantically identical is still an uncontrolled edit to a
    file that governs agent behaviour, and should require a registry update.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PromptLibrary:
    """Loads, validates and resolves versioned prompts."""

    def __init__(self, prompts_dir: Path | None = None, verify_hashes: bool = True):
        self.dir = Path(prompts_dir) if prompts_dir else PROMPTS_DIR
        self.registry_path = self.dir / "registry.json"
        self.verify_hashes = verify_hashes
        self._prompts: dict[tuple[str, str], Prompt] = {}
        self._active: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not self.registry_path.exists():
            raise PromptLibraryError(f"No registry at {self.registry_path}")

        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))

        for entry in registry["prompts"]:
            path = self.dir / entry["file"]
            if not path.exists():
                raise PromptLibraryError(
                    f"Registry lists {entry['file']} but the file is missing."
                )

            actual = sha256_of(path)
            if self.verify_hashes and entry.get("sha256") and entry["sha256"] != actual:
                raise PromptLibraryError(
                    f"{entry['file']} has been modified without a registry update.\n"
                    f"  registry: {entry['sha256']}\n"
                    f"  on disk:  {actual}\n"
                    f"Bump the version and re-stamp with tools/stamp_registry.py."
                )

            data = json.loads(path.read_text(encoding="utf-8"))
            prompt = Prompt(
                id=data["id"],
                version=data["version"],
                status=data["status"],
                scenario=data["scenario"],
                system=data["system"],
                user_template=data["user_template"],
                required_slots=data["required_slots"],
                few_shot=data.get("few_shot", []),
                route_confidence_threshold=data.get("route_confidence_threshold", 0.6),
                changelog=data.get("changelog", []),
                source_file=entry["file"],
                sha256=actual,
            )
            self._validate(prompt, entry)
            self._prompts[(prompt.id, prompt.version)] = prompt

        for scenario, version in registry["active"].items():
            if (scenario, version) not in self._prompts:
                raise PromptLibraryError(
                    f"Registry marks {scenario}@{version} active but it was not loaded."
                )
            if self._prompts[(scenario, version)].status != "active":
                raise PromptLibraryError(
                    f"{scenario}@{version} is pinned active in the registry but its "
                    f"own status field says '{self._prompts[(scenario, version)].status}'."
                )
            self._active[scenario] = version

    def _validate(self, prompt: Prompt, entry: dict) -> None:
        if prompt.id != entry["id"] or prompt.version != entry["version"]:
            raise PromptLibraryError(
                f"{entry['file']} declares {prompt.ref} but the registry lists "
                f"{entry['id']}@{entry['version']}."
            )

        unknown = self._slots_in(prompt.user_template) - KNOWN_SLOTS
        if unknown:
            raise PromptLibraryError(
                f"{prompt.ref} references slots the assembler cannot fill: "
                f"{sorted(unknown)}"
            )

        missing = set(prompt.required_slots) - self._slots_in(prompt.user_template)
        if missing:
            raise PromptLibraryError(
                f"{prompt.ref} requires slots {sorted(missing)} that its template "
                f"never uses."
            )

        # A changelog that does not reach the current version means someone
        # bumped the version without recording why.
        if prompt.changelog and prompt.changelog[-1]["version"] != prompt.version:
            raise PromptLibraryError(
                f"{prompt.ref} has no changelog entry for its own version."
            )

    @staticmethod
    def _slots_in(template: str) -> set[str]:
        import string

        return {
            field
            for _, field, _, _ in string.Formatter().parse(template)
            if field
        }

    def get(self, scenario: str, version: str | None = None) -> Prompt:
        """Resolve a prompt, defaulting to the registry's active version."""
        if version is None:
            if scenario not in self._active:
                raise PromptLibraryError(f"No active version for scenario '{scenario}'.")
            version = self._active[scenario]
        key = (scenario, version)
        if key not in self._prompts:
            raise PromptLibraryError(f"Unknown prompt {scenario}@{version}.")
        return self._prompts[key]

    def scenarios(self) -> list[str]:
        return sorted(self._active)

    def active_map(self) -> dict[str, str]:
        """Scenario -> active version. Surfaced by the service /v1/health."""
        return dict(self._active)
