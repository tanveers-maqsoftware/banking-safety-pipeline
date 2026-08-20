"""Shared fixtures and corpus helpers for the safety tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


CORPUS_PATH = Path(__file__).parent / "corpora" / "injection.json"


@pytest.fixture(scope="module")
def injection_corpus() -> dict:
    """Load the injection corpus once for aggregate tests."""
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def corpus_params(items: list[dict], accepted_key: str) -> list[pytest.ParameterSet]:
    """Build test parameters and preserve documented residual-risk xfails."""
    parameters = []
    for item in items:
        marks = []
        if item.get(accepted_key):
            marks.append(
                pytest.mark.xfail(
                    strict=True,
                    reason=f"accepted residual risk: {item['id']}",
                )
            )
        parameters.append(pytest.param(item, id=item["id"], marks=marks))
    return parameters
