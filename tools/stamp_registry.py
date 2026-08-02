"""Regenerate prompts/registry.json from the prompt files on disk.

Run this after intentionally editing a prompt AND bumping its version. It
recomputes every sha256 so the integrity check in safety/library.py passes
again. If you run it without bumping the version you have defeated the point of
the check -- the whole mechanism is there to make an unversioned edit loud.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety.library import PROMPTS_DIR, sha256_of  # noqa: E402


def main() -> int:
    files = sorted(p for p in PROMPTS_DIR.glob("*.json") if p.name != "registry.json")
    if not files:
        print("No prompt files found.")
        return 1

    entries = []
    active: dict[str, str] = {}

    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))
        entries.append(
            {
                "id": data["id"],
                "version": data["version"],
                "status": data["status"],
                "file": path.name,
                "sha256": sha256_of(path),
            }
        )
        if data["status"] == "active":
            if data["id"] in active:
                print(
                    f"ERROR: {data['id']} has two active versions "
                    f"({active[data['id']]} and {data['version']}).",
                    file=sys.stderr,
                )
                return 1
            active[data["id"]] = data["version"]

    registry = {
        "schema_version": "1.0",
        "description": (
            "Versioned prompt library for the Copilot Studio retail banking "
            "support agent. 'active' pins the version served at runtime; "
            "sha256 values are verified on load by safety/library.py."
        ),
        "active": dict(sorted(active.items())),
        "prompts": sorted(entries, key=lambda e: (e["id"], e["version"])),
    }

    out = PROMPTS_DIR / "registry.json"
    out.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote {out}")
    for scenario, version in registry["active"].items():
        print(f"  active: {scenario}@{version}")
    superseded = [e for e in entries if e["status"] != "active"]
    for entry in superseded:
        print(f"  {entry['status']}: {entry['id']}@{entry['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
