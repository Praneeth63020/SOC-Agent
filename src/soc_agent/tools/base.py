"""Tool layer: narrow, schema-validated, audited functions that Hermes may call.

Every tool is declared as a ToolSpec and registered into Hermes's tool registry
under ONE toolset ("soc"). The Hermes agent is created with
enabled_toolsets=["soc"], so the model never sees Hermes's built-in tools
(terminal, browser, files, ...). Calls to anything else are refused by Hermes.

Every call goes through the same wrapper (`wrap`):
  1. find the investigation the call belongs to (Hermes passes task_id)
  2. check the tool is enabled for this phase of the run         -> "denied"
  3. (optional) spec.prepare completes the arguments from this run's state (audited as "notes"),
     then validate the arguments against the tool's JSON schema  -> "rejected"
  4. check the tool's permission against what the run allows     -> "denied"
  5. run the handler with a timeout (default 5 s)                 -> "timeout"
     ToolRejection -> "rejected"; ToolFailure or any other exception -> "error"
     (fault injection, for tests and demos, replaces the handler here)
  6. validate the result against the tool's OUTPUT schema; a malformed result
     is withheld and becomes "error" (predictable outputs)
  7. remember the evidence refs the result returned (evidence-source read tools
     only), so a later submission can only cite refs this run actually saw, and
     keep the full result for correlate_evidence
     (write_internal handlers run inline, without the timeout thread)
  8. append an audit entry (seq, tool, permission, arguments, status, result
     (size-capped), result_summary, evidence_refs, fault_injected, timeout_s,
     started_at, finished_at, duration_ms)
The result always goes back to the model as JSON, errors included, so it can
correct itself instead of guessing. A failed or timed-out call never returns data.
"""
from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from soc_agent.config import FAULT_KINDS, PROJECT_ROOT
from soc_agent.schemas import problems

TOOLSET = "soc"
PERMISSIONS = ("read", "write_internal", "disruptive")
# read            look up evidence (alert, logs, IP reputation, CVEs, asset context)
# write_internal  write to the agent's own records (e.g. submit a plan / report)
# disruptive      would change a real system (block, disable, isolate): never allowed
#                 inside a run and never registered with Hermes (register_tools refuses it). The agent
#                 can only REQUEST such an action (request_action, write_internal); an analyst decides
#                 and executes it - simulated - through approvals.py, which has no tool wrapper at all.
RUN_PERMISSIONS = ("read", "write_internal")
STATUSES = ("ok", "rejected", "denied", "error", "timeout")
DEFAULT_TOOL_TIMEOUT_S = 5.0
AUDIT_RESULT_MAX_CHARS = 20_000                   # larger arguments / results are stored as a preview
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"


class ToolRejection(Exception):
    """Raised by a handler when the request is understood but not acceptable."""

    def __init__(self, message: str, problems: list[str] | None = None, hint: str | None = None):
        super().__init__(message)
        self.payload: dict[str, Any] = {"error": message}
        if problems:
            self.payload["problems"] = problems
        if hint:
            self.payload["hint"] = hint


class ToolFailure(Exception):
    """Raised by a handler that could not do its job (e.g. a data file is missing or corrupt)."""

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.payload: dict[str, Any] = {"error": message, "retryable": retryable}


class _TimedOut(Exception):
    pass


_MODEL_SCHEMA_DROP = {"$schema", "$id", "title", "contains", "pattern", "format", "anyOf", "oneOf", "allOf",
                      "not", "if", "then", "else", "errorMessage", "$comment"}


def model_schema(schema: dict) -> dict:
    """The schema without keywords some OpenAI-compatible backends reject in tool definitions
    (pattern, format, contains, anyOf, ...). Nothing is lost: the wrapper (or the handler)
    validates every call against the FULL schema."""
    out = {k: v for k, v in schema.items() if k not in _MODEL_SCHEMA_DROP}
    if isinstance(out.get("properties"), dict):
        out["properties"] = {name: model_schema(sub) for name, sub in out["properties"].items()}
    if isinstance(out.get("items"), dict):
        out["items"] = model_schema(out["items"])
    return out


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict                                   # FULL JSON schema of the arguments
    handler: Callable[[dict, "RunContext"], dict]
    permission: str = "read"
    output_schema: dict | None = None                  # every successful result is validated against it
    summarize: Callable[[dict], str] | None = None     # one line for the audit entry / trace
    timeout_s: float | None = None                     # None = the run's tool_timeout_s
    retry_hint: str | None = None                      # hint returned with a schema rejection (default: generic)
    # field -> what to send when that required field is missing (appended to the schema problem; Day 5: the live
    # model left out "containment" when nothing needed containing, and the bare schema message did not say what to
    # put there)
    field_hints: dict[str, str] | None = None
    # runs BEFORE validation and may complete the arguments from this run's own state (e.g. fields of the
    # previous submission the model left out of a resubmission); returns (arguments, notes). The completed
    # arguments then get the full validation, and the notes are audited and returned to the model.
    prepare: Callable[[dict, "RunContext"], tuple[dict, list[str]]] | None = None
    # its refs become citable evidence (step 7). False for read tools that only pass data through or derive
    # from other results (get_alert: an alert could carry a forged "evidence_ref"; correlate_evidence)
    evidence_source: bool = True

    def __post_init__(self) -> None:
        if self.permission not in PERMISSIONS:
            raise ValueError(f"{self.name}: unknown permission {self.permission!r}")

    def hermes_schema(self) -> dict:
        """What the model is sent: the simplified schema (see model_schema)."""
        return {"name": self.name, "description": self.description, "parameters": model_schema(self.parameters)}


@dataclass
class RunContext:
    """Per-investigation state the tools can read and write (looked up by task_id)."""
    investigation_id: str
    alert: dict
    allowed_permissions: tuple[str, ...] = RUN_PERMISSIONS
    tool_calls: list[dict] = field(default_factory=list)     # the audit trail
    plan: dict | None = None
    # tools enabled for this phase (Hermes's registry is process-global, so a phase must not reach
    # tools registered for another one); None = no restriction (direct calls, unit tests)
    allowed_tools: frozenset[str] | None = None
    data_dir: Path = DEFAULT_DATA_DIR
    tool_timeout_s: float = DEFAULT_TOOL_TIMEOUT_S
    faults: dict[str, str] = field(default_factory=dict)     # tool name -> "timeout" | "error" | "malformed"
    audit_result_max_chars: int = AUDIT_RESULT_MAX_CHARS
    evidence_refs: dict[str, str] = field(default_factory=dict)   # ref -> tool that returned it in this run
    evidence_log: dict | None = None
    # full results of every successful read call in this run, in call order ({seq, tool, arguments, result});
    # the audit trail may hold only a size-capped preview. correlate_evidence works on these and nothing else.
    evidence_results: list[dict] = field(default_factory=list)
    findings: dict | None = None                                 # accepted submit_findings arguments
    findings_check: dict | None = None                           # correlation + rubric the findings were checked against
    findings_draft: dict | None = None                           # last submit_findings arguments (after prepare)
    findings_flawed_fields: list[str] = field(default_factory=list)   # fields the last rejected findings got wrong
    # Day 4 (report phase): the investigation's database (store.Store), the evidence refs of the earlier phases
    # with their entities (ref -> {tool, account, host, ips, excerpt, ...}), and what the agent submitted
    store: Any = field(default=None, repr=False, compare=False)
    evidence_index: dict[str, dict] = field(default_factory=dict)
    report_content: dict | None = None
    phase: str | None = None
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
    model at the exact place instead of echoing the whole string back.)
    Hermes also wraps a bare string for an array argument in a list, so ["[{...broken"] for an
    array of objects is the same mistake."""
    out = []
    for name, value in args.items():
        prop = (schema.get("properties") or {}).get(name) or {}
        want = prop.get("type")
        if (want == "array" and isinstance(value, list) and len(value) == 1 and isinstance(value[0], str)
                and (prop.get("items") or {}).get("type") in ("object", "array")
                and value[0].lstrip().startswith(("[", "{"))):
            value = value[0]                     # Hermes's coercion of a malformed JSON string
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


def collect_refs(result: Any) -> list[str]:
    """Every evidence_ref (str) / evidence_refs (list of str) in a result, in order, without duplicates."""
    found: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for k, x in v.items():
                if k == "evidence_ref" and isinstance(x, str):
                    found.append(x)
                elif k == "evidence_refs" and isinstance(x, list):
                    found.extend(r for r in x if isinstance(r, str))
                else:
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(result)
    return list(dict.fromkeys(found))


def _fault_handler(spec: ToolSpec, kind: str, cancel: threading.Event, timeout_s: float) -> Callable[[], dict]:
    def run() -> dict:
        if kind == "timeout":                 # hang until the wrapper gives up (then exit promptly)
            cancel.wait(timeout_s * 4 + 1)
            return {"error": "[FAULT INJECTION] late result (discarded)"}
        if kind == "error":
            raise ToolFailure(f"[FAULT INJECTION] {spec.name}: simulated data source failure.")
        return {"unexpected": "[FAULT INJECTION] malformed tool output"}
    return run


def _run_with_timeout(fn: Callable[[], Any], timeout_s: float, name: str) -> Any:
    ex = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"soc-tool-{name}")
    fut = ex.submit(fn)
    try:
        return fut.result(timeout=timeout_s)
    except FuturesTimeout:
        if fut.done():            # the handler itself raised TimeoutError: that is an error, not our timeout
            raise
        raise _TimedOut() from None
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


def _has_lone_surrogate(value: Any) -> bool:
    if isinstance(value, str):
        return any("\ud800" <= ch <= "\udfff" for ch in value)
    if isinstance(value, dict):
        return any(_has_lone_surrogate(k) or _has_lone_surrogate(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_has_lone_surrogate(v) for v in value)
    return False


def _execute(spec: ToolSpec, args: Any, ctx: RunContext) -> tuple[str, Any, str | None]:
    """Validate, permission-check and run one call. Returns (status, result, injected fault)."""
    if not isinstance(args, dict):
        return "rejected", {"error": "Arguments must be a JSON object."}, None
    if _has_lone_surrogate(args):          # valid JSON ("\\ud800"), but not text: it could not be stored or hashed
        return "rejected", {"error": "Arguments contain an invalid Unicode character (a lone surrogate). Send plain "
                                     "text."}, None
    if ctx.allowed_tools is not None and spec.name not in ctx.allowed_tools:
        return "denied", {"error": f"Tool {spec.name} is not available in this phase of the investigation. "
                                   f"Available: {', '.join(sorted(ctx.allowed_tools))}."}, None
    notes: list[str] = []
    if spec.prepare is not None:
        try:
            args, notes = spec.prepare(args, ctx)
        except ToolRejection as e:
            return "rejected", e.payload, None
    status, result, fault = _validate_and_run(spec, args, ctx)
    if notes and isinstance(result, dict):
        result = {**result, "notes": notes}
    return status, result, fault


def _with_field_hint(problem: str, hints: dict[str, str] | None) -> str:
    """A "'x' is a required property" problem plus what to send for x, if the tool says so."""
    m = re.search(r"'([A-Za-z_]+)' is a required property", problem)
    return f"{problem}: {hints[m.group(1)]}" if hints and m and m.group(1) in hints else problem


def _validate_and_run(spec: ToolSpec, args: dict, ctx: RunContext) -> tuple[str, Any, str | None]:
    if errs := problems(args, spec.parameters):
        explained = json_string_problems(args, spec.parameters)
        covered = {p.split(":", 1)[0] for p in explained}       # drop the generic errors under those arguments
        errs = explained + [e for e in errs if e.split(":", 1)[0].split("/", 1)[0] not in covered]
        errs = [_with_field_hint(e, spec.field_hints) for e in errs]
        return "rejected", {"error": f"Invalid arguments for {spec.name}.", "problems": errs,
                            "hint": spec.retry_hint or "Call the tool again with arguments matching its schema."}, None
    if spec.permission not in ctx.allowed_permissions:
        return "denied", {"error": f"Tool {spec.name} needs permission '{spec.permission}', "
                                   "which this investigation does not have. Recommend the "
                                   "action for analyst_review instead."}, None

    timeout_s = spec.timeout_s or ctx.tool_timeout_s
    fault = ctx.faults.get(spec.name)
    cancel = threading.Event()
    fn = (_fault_handler(spec, fault, cancel, timeout_s) if fault in FAULT_KINDS
          else lambda: spec.handler(args, ctx))
    # write_internal handlers only validate and store in memory: they run inline (under the run's lock), because
    # a timed-out submission must never be committed later by a background thread
    inline = spec.permission == "write_internal" and fault not in FAULT_KINDS
    try:
        result = fn() if inline else _run_with_timeout(fn, timeout_s, spec.name)
    except _TimedOut:
        return "timeout", {"error": f"{spec.name} timed out after {timeout_s:g} s. No data was returned: "
                                    "record this step as failed and do not guess its result.",
                           "retryable": True}, fault
    except ToolRejection as e:
        return "rejected", e.payload, fault
    except ToolFailure as e:
        return "error", e.payload, fault
    except Exception as e:      # a tool must never crash the agent
        return "error", {"error": f"{spec.name} failed: {type(e).__name__}: {e}", "retryable": False}, fault
    finally:
        cancel.set()

    if not isinstance(result, dict):
        return "error", {"error": f"{spec.name} returned a {type(result).__name__}, not a JSON object; "
                                  "the result was withheld.", "retryable": False}, fault
    if spec.output_schema is not None and (errs := problems(result, spec.output_schema)):
        return "error", {"error": f"{spec.name} returned a result that does not match its output schema; "
                                  "the result was withheld. Do not guess what it contained.",
                         "problems": errs, "retryable": False}, fault
    return "ok", result, fault


def _capped(value: Any, limit: int) -> tuple[Any, bool]:
    """The value itself, or a preview of its JSON if that is longer than `limit` characters."""
    text = json.dumps(value, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return value, False
    return {"_truncated": True, "original_chars": len(text), "preview": text[:limit]}, True


def _summary(spec: ToolSpec, status: str, result: Any) -> str:
    if status != "ok":
        msg = result.get("error", "") if isinstance(result, dict) else str(result)
        return f"{status}: {msg}"[:300]
    if spec.summarize:
        try:
            return spec.summarize(result)[:300]
        except Exception as e:       # a summary must never turn a good result into a failure
            return f"ok (summary unavailable: {type(e).__name__})"
    return "ok: " + ", ".join(sorted(result))[:290] if isinstance(result, dict) else "ok"


def wrap(spec: ToolSpec) -> Callable[..., str]:
    """The single wrapper every tool runs through (Hermes calls handler(args, task_id=..., ...))."""

    def handler(args: Any, task_id: str | None = None, **_: Any) -> str:
        started, t0 = _now(), time.perf_counter()
        with _LOCK:
            ctx = _RUNS.get(task_id or "")
        if ctx is None:
            return json.dumps({"error": "No active investigation for this tool call."})

        with ctx.lock:
            status, result, fault = _execute(spec, args, ctx)
            evidence = status == "ok" and spec.permission == "read" and spec.evidence_source
            refs = collect_refs(result) if evidence else []
            for ref in refs:
                ctx.evidence_refs.setdefault(ref, spec.name)
            if evidence:
                ctx.evidence_results.append({"seq": len(ctx.tool_calls) + 1, "tool": spec.name,
                                             "arguments": args, "result": result})
            stored_args, args_cut = _capped(args, ctx.audit_result_max_chars)
            stored_result, result_cut = _capped(result, ctx.audit_result_max_chars)
            ctx.tool_calls.append({
                "seq": len(ctx.tool_calls) + 1, "tool": spec.name, "permission": spec.permission,
                "arguments": stored_args, "status": status, "result": stored_result,
                "result_summary": _summary(spec, status, result), "result_truncated": result_cut or args_cut,
                "evidence_refs": refs, "fault_injected": fault, "timeout_s": spec.timeout_s or ctx.tool_timeout_s,
                "started_at": started, "finished_at": _now(),
                "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            })
        return json.dumps(result, ensure_ascii=False, default=str)

    handler.__name__ = f"soc_tool_{spec.name}"
    return handler


def call_tool(spec: ToolSpec, args: Any, ctx: RunContext) -> tuple[dict, dict]:
    """Run one call through the same wrapper outside Hermes (CLI `tool` command, tests).
    Returns (result as the model would see it, audit entry)."""
    open_run(ctx)
    try:
        out = json.loads(wrap(spec)(args, task_id=ctx.investigation_id))
    finally:
        close_run(ctx.investigation_id)
    return out, ctx.tool_calls[-1]


def register_tools(specs: list[ToolSpec]) -> list[str]:
    """Register (or re-register) our tools in Hermes's process-global registry under TOOLSET."""
    from tools.registry import registry          # Hermes import (heavy) only when needed

    if disruptive := [s.name for s in specs if s.permission not in RUN_PERMISSIONS]:
        # block_ip / disable_account / isolate_host never reach the model: they exist only behind the analyst
        # approval path (approvals.py), and even there only as a simulation
        raise ValueError(f"Refusing to register {disruptive} with Hermes: permission 'disruptive' is never "
                         "available to the agent (it may only call request_action).")
    for spec in specs:
        registry.register(name=spec.name, toolset=TOOLSET, schema=spec.hermes_schema(),
                          handler=wrap(spec), description=spec.description)
        entry = registry.get_entry(spec.name)
        # Hermes silently refuses a name that shadows a tool from another toolset
        if entry is None or entry.toolset != TOOLSET:
            raise RuntimeError(f"Tool {spec.name!r} could not be registered in toolset {TOOLSET!r}")
    return [s.name for s in specs]
