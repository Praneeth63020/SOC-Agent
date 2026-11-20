"""JSON-schema loading and validation (alert input, plan output, tool arguments)."""
from __future__ import annotations

import json
from functools import lru_cache

from jsonschema import Draft202012Validator, FormatChecker

from soc_agent.config import PROJECT_ROOT

SCHEMA_DIR = PROJECT_ROOT / "schemas"
MAX_SHOWN = 120         # longest value quoted back in a problem message


class SchemaError(ValueError):
    """Raised with a readable list of problems."""

    def __init__(self, what: str, problems: list[str]):
        self.problems = problems
        super().__init__(f"{what} is invalid: " + "; ".join(problems))


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))


def problems(instance, schema: dict, limit: int = 8) -> list[str]:
    v = Draft202012Validator(schema, format_checker=FormatChecker())
    errs = sorted(v.iter_errors(instance), key=lambda e: [str(p) for p in e.path])
    out = []
    for e in errs[:limit]:
        msg = e.message
        shown = repr(e.instance)
        if len(shown) > MAX_SHOWN:          # never echo a huge value (e.g. a whole plan) back
            msg = msg.replace(shown, f"{shown[:MAX_SHOWN]}... ({len(shown)} characters)")
        if e.validator == "pattern" and isinstance(e.schema, dict) and e.schema.get("description"):
            msg = f"{e.instance!r} is not valid ({e.schema['description']})"   # readable, not a regex
        out.append(f"{'/'.join(map(str, e.path)) or '(root)'}: {msg}")
    return out


def validate(instance, schema_name: str, what: str | None = None) -> None:
    p = problems(instance, load_schema(schema_name))
    if p:
        raise SchemaError(what or schema_name, p)
