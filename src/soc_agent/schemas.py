"""JSON-schema loading and validation (alert input, plan output, tool arguments and results)."""
from __future__ import annotations

import json
from functools import lru_cache

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

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


@lru_cache(maxsize=None)
def load_tool_schema(tool: str, kind: str) -> dict:
    """schemas/tools/<tool>.<kind>.json, kind = "input" | "output"."""
    if kind not in ("input", "output"):
        raise ValueError(f"kind must be 'input' or 'output', not {kind!r}")
    return json.loads((SCHEMA_DIR / "tools" / f"{tool}.{kind}.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _registry() -> Registry:
    """Every local schema by its $id, so a $ref between our schemas (e.g. assessment -> findings) resolves
    locally; nothing is ever fetched over the network."""
    resources = []
    for path in sorted(SCHEMA_DIR.rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and doc.get("$id"):
            resources.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources)


def problems(instance, schema: dict, limit: int = 8) -> list[str]:
    v = Draft202012Validator(schema, format_checker=FormatChecker(), registry=_registry())
    errs = sorted(v.iter_errors(instance), key=lambda e: [str(p) for p in e.path])
    out = []
    for e in errs[:limit]:
        msg = e.message
        shown = repr(e.instance)
        if len(shown) > MAX_SHOWN:          # never echo a huge value (e.g. a whole plan) back
            msg = msg.replace(shown, f"{shown[:MAX_SHOWN]}... ({len(shown)} characters)")
        if e.validator == "maxLength":
            msg += f" (maximum {e.validator_value} characters; shorten it)"
        elif e.validator == "type" and e.validator_value == "object" and isinstance(e.instance, str):
            msg += " (send a JSON object here, e.g. {\"statement\": \"...\", \"evidence_refs\": [\"...\"]}, not a string)"
        if e.validator == "pattern" and isinstance(e.schema, dict) and e.schema.get("description"):
            msg = f"{e.instance!r} is not valid ({e.schema['description']})"   # readable, not a regex
        elif e.validator in ("anyOf", "oneOf") and isinstance(e.schema, dict) and e.schema.get("errorMessage"):
            msg = e.schema["errorMessage"]                     # e.g. "give at least one filter besides source"
        out.append(f"{'/'.join(map(str, e.path)) or '(root)'}: {msg}")
    return out


def validate(instance, schema_name: str, what: str | None = None) -> None:
    p = problems(instance, load_schema(schema_name))
    if p:
        raise SchemaError(what or schema_name, p)
