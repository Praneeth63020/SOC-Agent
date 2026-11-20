"""Tool layer: narrow, schema-validated, audited functions that Hermes may call.

Every tool is declared as a ToolSpec and registered into Hermes's tool registry
under ONE toolset ("soc"). The Hermes agent is created with
enabled_toolsets=["soc"], so the model never sees Hermes's built-in tools
(terminal, browser, files, ...). Calls to anything else are refused by Hermes.

Every call goes through the same wrapper (`wrap`):
  1. find the investigation the call belongs to (Hermes passes task_id)
  2. validate the arguments against the tool's JSON schema -> "rejected"
  3. check the tool's permission against what the run allows -> "denied"
  4. run the handler; ToolRejection -> "rejected", any other exception -> "error"
  5. append an audit entry (seq, tool, permission, arguments, status, result,
     started_at, finished_at, duration_ms)
The result always goes back to the model as JSON, errors included, so it can
correct itself instead of guessing.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from soc_agent.schemas import problems

TOOLSET = "soc"
PERMISSIONS = ("read", "write_internal", "disruptive")
# read            look up evidence (alert, logs, IP reputation, CVEs, asset context)
# write_internal  write to the agent's own records (e.g. submit a plan / report)
# disruptive      would change a real system (block, disable, isolate): never allowed
#                 inside a run; needs the human approval workflow (Day 4)
RUN_PERMISSIONS = ("read", "write_internal")


class ToolRejection(Exception):
    """Raised by a handler when the request is understood but not acceptable."""

    def __init__(self, message: str, problems: list[str] | None = None, hint: str | None = None):
        super().__init__(message)
        self.payload: dict[str, Any] = {"error": message}
        if problems:
            self.payload["problems"] = problems
        if hint:
            self.payload["hint"] = hint


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict                                   # JSON schema of the arguments
    handler: Callable[[dict, "RunContext"], dict]
    permission: str = "read"

    def __post_init__(self) -> None:
        if self.permission not in PERMISSIONS:
            raise ValueError(f"{self.name}: unknown permission {self.permission!r}")

    def hermes_schema(self) -> dict:
        return {"name": self.name, "description": self.description, "parameters": self.parameters}


@dataclass
class RunContext:
    """Per-investigation state the tools can read and write (looked up by task_id)."""
    investigation_id: str
    alert: dict
    allowed_permissions: tuple[str, ...] = RUN_PERMISSIONS
    tool_calls: list[dict] = field(default_factory=list)     # the audit trail
    plan: dict | None = None
    # one tool call at a time per investigation, so "check attempts / accept one plan / audit"
    # is atomic even if a runtime ever dispatches tool calls in parallel
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)


_RUNS: dict[str, RunContext] = {}
_LOCK = threading.Lock()


def open_run(ctx: RunContext) -> None:
    with _LOCK:
        _RUNS[ctx.investigation_id] = ctx


def close_run(investigation_id: str) -> None:
    with _LOCK:
        _RUNS.pop(investigation_id, None)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def json_string_problems(args: dict, schema: dict) -> list[str]:
    """Explain an object/array argument that arrived as a string. (Hermes already decodes
    strings that are valid JSON, so what reaches us is usually malformed JSON; point the
    model at the exact place instead of echoing the whole string back.)"""
    out = []
    for name, value in args.items():
        want = ((schema.get("properties") or {}).get(name) or {}).get("type")
        if not isinstance(value, str) or want not in ("object", "array"):
            continue
        msg = f"{name}: must be a JSON {want}, not a string"
        try:
            json.loads(value)
            out.append(msg + " containing JSON.")
        except ValueError as e:
            pos = getattr(e, "pos", 0) or 0
            near = value[max(0, pos - 80):pos + 20].replace("\n", " ")
            out.append(f"{msg}. The string is also not valid JSON ({getattr(e, 'msg', e)} at character "
                       f"{pos}, near: ...{near}...).")
    return out


def _execute(spec: ToolSpec, args: Any, ctx: RunContext) -> tuple[str, Any]:
    """Validate, permission-check and run one call. Returns (status, result)."""
    status, result = "ok", None
    if not isinstance(args, dict):
        status, result = "rejected", {"error": "Arguments must be a JSON object."}
    elif errs := problems(args, spec.parameters):
        explained = json_string_problems(args, spec.parameters)
        covered = {p.split(":", 1)[0] for p in explained}       # drop the generic type error for those
        errs = explained + [e for e in errs if not (e.split(":", 1)[0] in covered and "is not of type" in e)]
        status, result = "rejected", {"error": f"Invalid arguments for {spec.name}.", "problems": errs,
                                      "hint": "Call the tool again with arguments matching its schema."}
    elif spec.permission not in ctx.allowed_permissions:
        status, result = "denied", {"error": f"Tool {spec.name} needs permission '{spec.permission}', "
                                             "which this investigation does not have. Recommend the "
                                             "action for analyst_review instead."}
    else:
        try:
            result = spec.handler(args, ctx)
        except ToolRejection as e:
            status, result = "rejected", e.payload
        except Exception as e:      # a tool must never crash the agent
            status, result = "error", {"error": f"{spec.name} failed: {type(e).__name__}: {e}"}
    return status, result


def wrap(spec: ToolSpec) -> Callable[..., str]:
    """The single wrapper every tool runs through (Hermes calls handler(args, task_id=..., ...))."""

    def handler(args: Any, task_id: str | None = None, **_: Any) -> str:
        started, t0 = _now(), time.perf_counter()
        with _LOCK:
            ctx = _RUNS.get(task_id or "")
        if ctx is None:
            return json.dumps({"error": "No active investigation for this tool call."})

        with ctx.lock:
            status, result = _execute(spec, args, ctx)
            ctx.tool_calls.append({
                "seq": len(ctx.tool_calls) + 1, "tool": spec.name, "permission": spec.permission,
                "arguments": args, "status": status, "result": result,
                "started_at": started, "finished_at": _now(),
                "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            })
        return json.dumps(result, ensure_ascii=False, default=str)

    handler.__name__ = f"soc_tool_{spec.name}"
    return handler


def register_tools(specs: list[ToolSpec]) -> list[str]:
    """Register (or re-register) our tools in Hermes's process-global registry under TOOLSET."""
    from tools.registry import registry          # Hermes import (heavy) only when needed

    for spec in specs:
        registry.register(name=spec.name, toolset=TOOLSET, schema=spec.hermes_schema(),
                          handler=wrap(spec), description=spec.description)
        entry = registry.get_entry(spec.name)
        # Hermes silently refuses a name that shadows a tool from another toolset
        if entry is None or entry.toolset != TOOLSET:
            raise RuntimeError(f"Tool {spec.name!r} could not be registered in toolset {TOOLSET!r}")
    return [s.name for s in specs]
