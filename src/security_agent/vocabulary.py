"""The category vocabulary, read from the schema that enforces it.

There was one list of category names in `prompts/findings.schema.json`, which
the model is held to, and a second list in my head, which everything else was
written against. They did not match: the corpus scored against `authorization`,
`path_traversal` and `open_redirect`, none of which the agent can ever emit, so
seven cases were scored as misses that were never given a chance to pass. The
test that should have caught it asserted the map against a set typed from the
same wrong assumption — a test that shares the code's premise tests nothing.

So there is now one source, and it is the schema. Anything that needs to name a
category asks here, and anything that accepts one from an operator is checked
here, at start-up, where a typo is a message rather than a silent no-op.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Tuple

SCHEMA_NAME = "findings.schema.json"


class VocabularyError(Exception):
    """The schema could not be read, or does not say what it must."""


def _schema_path() -> Path:
    """The schema shipped with the agent, never one from the reviewed repo.

    Same reasoning as the prompts: a repository under review must not be able
    to widen the vocabulary its own findings are checked against.
    """
    here = Path(__file__).resolve()
    for base in (here.parents[2] / "prompts", here.parent / "prompts"):
        candidate = base / SCHEMA_NAME
        if candidate.is_file():
            return candidate
    raise VocabularyError(
        "cannot find {} next to the agent; the category vocabulary is defined "
        "there and has no fallback".format(SCHEMA_NAME))


@lru_cache(maxsize=1)
def categories() -> Tuple[str, ...]:
    """Every category a finding may carry, in schema order."""
    try:
        schema = json.loads(_schema_path().read_text(encoding="utf-8"))
        enum = (schema["properties"]["findings"]["items"]
                ["properties"]["category"]["enum"])
    except VocabularyError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise VocabularyError(
            "{} does not define findings[].category as an enum: {}".format(
                SCHEMA_NAME, exc)) from exc
    if not enum:
        raise VocabularyError("the category enum in {} is empty".format(SCHEMA_NAME))
    return tuple(str(value) for value in enum)


def is_category(name: str) -> bool:
    return name.strip().lower() in {c.lower() for c in categories()}


def normalise(name: str) -> str:
    """Match an operator's spelling to the schema's, or return "" if it is not one.

    Case and separator only. `Path-Traversal` and `path-traversal` are the same
    intent; `path_traversal` is a different string but unmistakably the same
    word, and rejecting it over an underscore helps nobody. Anything further
    apart than that is a typo worth reporting rather than guessing at.
    """
    wanted = name.strip().lower().replace("_", "-")
    for category in categories():
        if category.lower().replace("_", "-") == wanted:
            return category
    return ""
