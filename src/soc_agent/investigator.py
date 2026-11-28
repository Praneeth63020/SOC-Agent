"""Day 2 workflow: execute an accepted plan with the evidence tools -> validated evidence log.

The Hermes agent gets get_alert, the four evidence tools and submit_evidence_log
(nothing else), the plan's steps, and is asked to run each evidence step, saying
why before each call. Its output counts only if submit_evidence_log accepts it:
every cited evidence_ref must have been returned by that step's tool in this run,
and a failed / timed-out call must be recorded as failed (it returned no data).

No severity, verdict or recommendation is produced in this phase (Day 3).

The run record runs/<investigation_id>.investigation.json has the same format as
the planning record (phase "investigation", same investigation_id) plus a compact
`trace` of every tool call and the evidence log.
"""
from __future__ import annotations

import contextlib
import json
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from soc_agent import __version__
from soc_agent.config import Settings
from soc_agent.hermes_runtime import build_agent, console_text, exposed_tool_names
from soc_agent.mock_llm import SCENARIO_FAULTS, MockLLMServer
from soc_agent.planner import (HERMES_JSON_REPLIES, HERMES_STATS, PlanResult, _now, plan_investigation,
                               refused_tool_calls, refused_warnings)
from soc_agent.prompts import INVESTIGATOR_SYSTEM, investigator_task
from soc_agent.tools.base import RunContext, close_run, open_run
from soc_agent.tools.evidence import EVIDENCE_TOOLS
from soc_agent.tools.investigation import SUBMIT_EVIDENCE_LOG
from soc_agent.tools.planning import GET_ALERT

INVESTIGATION_TOOLS = [GET_ALERT, *EVIDENCE_TOOLS, SUBMIT_EVIDENCE_LOG]
MOCK_WARNING = "MOCK LLM: this evidence log was produced by a deterministic script, not by an AI model."
RECORD_SUFFIX = ".investigation.json"


@dataclass
class InvestigationResult:
    investigation_id: str
    alert_id: str
    plan_id: str | None
    status: str                         # "completed" (evidence log accepted) | "failed"
    evidence_log: dict | None
    trace: list[dict] = field(default_factory=list)
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    faults: dict = field(default_factory=dict)
    run_record: str | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def record_path(runs_dir: Path, investigation_id: str) -> Path:
    return Path(runs_dir) / f"{investigation_id}{RECORD_SUFFIX}"


def _call_reasons(messages: list, tool_names: set[str]) -> dict[str, deque]:
    """The model's text that accompanied each tool call, queued per tool name in call order.
    (Hermes does not pass tool_call ids to handlers; tools run one at a time, so per-name order
    lines up with the audit trail. Calls that never reached the wrapper are skipped: calls to
    tools outside the toolset, and calls Hermes answered itself for invalid JSON arguments.)"""
    replies = {m.get("tool_call_id"): m.get("content") for m in messages or []
               if isinstance(m, dict) and m.get("role") == "tool"}
    out: dict[str, deque] = defaultdict(deque)
    for m in messages or []:
        if not isinstance(m, dict) or m.get("role") != "assistant":
            continue
        text = m.get("content") if isinstance(m.get("content"), str) else None
        for tc in m.get("tool_calls") or []:
            if not isinstance(tc, dict):
                continue
            name = (tc.get("function") or {}).get("name")
            reply = replies.get(tc.get("id"))
            if name in tool_names and not (isinstance(reply, str) and reply.startswith(HERMES_JSON_REPLIES)):
                out[name].append((text or "").strip()[:300] or None)
    return out


def build_trace(tool_calls: list[dict], messages: list | None = None) -> list[dict]:
    """Compact, readable view of the audit trail: one row per tool call."""
    reasons = _call_reasons(messages or [], {c["tool"] for c in tool_calls})
    trace = []
    for c in tool_calls:
        queue = reasons.get(c["tool"])
        trace.append({
            "seq": c["seq"], "tool": c["tool"], "arguments": c["arguments"], "status": c["status"],
            "duration_ms": c["duration_ms"], "summary": c.get("result_summary"),
            "evidence_refs": c.get("evidence_refs", []), "fault_injected": c.get("fault_injected"),
            "reason": queue.popleft() if queue else None,
        })
    return trace


def run_investigation(alert: dict, plan: dict, settings: Settings, mock_scenario: str = "investigate_normal",
                      faults: dict | None = None) -> InvestigationResult:
    """Execute `plan` (the accepted, wrapped plan from planner.plan_investigation) for `alert`."""
    investigation_id = plan["investigation_id"]
    names = {t.name for t in INVESTIGATION_TOOLS}
    faults = {**settings.faults, **(SCENARIO_FAULTS.get(mock_scenario, {}) if settings.is_mock else {}),
              **(faults or {})}
    ctx = RunContext(investigation_id=investigation_id, alert=alert, plan=plan, allowed_tools=frozenset(names),
                     data_dir=settings.data_dir, tool_timeout_s=settings.tool_timeout_s, faults=faults)
    t0 = time.perf_counter()
    task = investigator_task(alert, plan)
    record: dict = {
        "investigation_id": investigation_id, "phase": "investigation", "plan_id": plan.get("plan_id"),
        "planning_record": f"{investigation_id}.json", "app_version": __version__, "started_at": _now(),
        "alert_id": alert["alert_id"], "synthetic_data": bool(alert.get("synthetic")),
        "alert": {k: v for k, v in alert.items() if k != "raw"}, "plan": plan,
        "llm": {"provider": settings.llm_provider, "model": settings.model, "mock": settings.is_mock,
                "mock_scenario": mock_scenario if settings.is_mock else None},
        "task": {"system_prompt": INVESTIGATOR_SYSTEM, "user_message": task,
                 "note": "Hermes prepends its own identity prompt before system_prompt."},
        "limits": {"max_iterations": settings.investigation_max_iterations, "tool_timeout_s": settings.tool_timeout_s},
        "fault_injection": faults, "exposed_tools": [],
    }
    warnings: list[str] = [MOCK_WARNING] if settings.is_mock else []
    if faults:
        warnings.append(f"FAULT INJECTION ACTIVE (testing only): {faults}")
    error, messages = None, []
    from soc_agent.store import save_phase, start_phase

    start_phase(settings, investigation_id, alert, "investigate")
    open_run(ctx)
    try:
        if unknown := sorted(set(faults) - names):
            raise ValueError(f"Fault injection names unknown tool(s) {unknown}; tools: {sorted(names)}")
        server_cm = MockLLMServer(mock_scenario) if settings.is_mock else contextlib.nullcontext()
        with server_cm as server:
            agent = build_agent(settings, INVESTIGATION_TOOLS, session_id=f"{investigation_id}-investigation",
                                base_url=server.base_url if server else None,
                                max_iterations=settings.investigation_max_iterations)
            record["exposed_tools"] = exposed_tool_names(agent)
            out = agent.run_conversation(task, system_message=INVESTIGATOR_SYSTEM, task_id=investigation_id)
        messages = out.get("messages", [])
        record["hermes"] = {k: out.get(k) for k in HERMES_STATS if k in out} | {"console": console_text(agent)}
        record["refused_tool_calls"] = refused_tool_calls(messages, names)
        warnings.extend(refused_warnings(record["refused_tool_calls"]))
        if ctx.evidence_log is None:
            reason = out.get("error") or out.get("final_response") or "no evidence log was submitted"
            raise RuntimeError(f"Agent did not produce an accepted evidence log: {str(reason)[:300]}")
        if out.get("failed"):
            warnings.append(f"Hermes reported a failure after the evidence log was accepted: {out.get('error')}")
    except Exception as e:      # always a structured result; an evidence log is never filled in by the app
        error = f"{type(e).__name__}: {e}"
    finally:
        close_run(investigation_id)

    by_status = defaultdict(list)
    for c in ctx.tool_calls:
        by_status[c["status"]].append(f"#{c['seq']} {c['tool']}")
    for status in ("timeout", "error", "rejected", "denied"):
        if by_status[status]:
            warnings.append(f"{len(by_status[status])} tool call(s) {status}: {', '.join(by_status[status])}.")
    failed_steps = [e["step"] for e in (ctx.evidence_log or {}).get("executed_steps", []) if e["outcome"] == "failed"]
    if failed_steps:
        warnings.append(f"Evidence is incomplete: plan step(s) {failed_steps} failed and returned no data.")

    duration = round((time.perf_counter() - t0) * 1000, 1)
    status = "completed" if ctx.evidence_log is not None and error is None else "failed"
    trace = build_trace(ctx.tool_calls, messages)
    record.update({"finished_at": _now(), "duration_ms": duration, "status": status, "error": error,
                   "warnings": warnings, "tool_calls": ctx.tool_calls, "trace": trace,
                   "evidence_refs_returned": len(ctx.evidence_refs), "evidence_log": ctx.evidence_log})
    settings.runs_dir.mkdir(parents=True, exist_ok=True)
    path = record_path(settings.runs_dir, investigation_id)
    if path.exists():           # a re-run of the same plan: keep the earlier record (audit), never overwrite it
        stamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        path.rename(path.with_name(f"{investigation_id}.investigation.{stamp}.json"))
    save_phase(settings, ctx, "investigate", record=record, allowed=names, messages=messages, status=status,
               error=error, warnings=warnings, output=ctx.evidence_log,
               mock_scenario=mock_scenario if settings.is_mock else None, run_record=str(path))
    # JSON export of the run record, written after the database audit (a write problem here never loses the
    # audit); errors="replace" keeps unencodable model text (e.g. a lone surrogate) from crashing the run
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str), encoding="utf-8", errors="replace")
    return InvestigationResult(investigation_id, alert["alert_id"], plan.get("plan_id"), status, ctx.evidence_log,
                               trace, error, warnings, faults, str(path), duration)


def investigate_alert(alert: dict, settings: Settings, mock_scenario: str = "investigate_normal",
                      faults: dict | None = None) -> tuple[PlanResult, InvestigationResult | None]:
    """Day 1 plan, then Day 2 investigation (only if a plan was accepted)."""
    plan_res = plan_investigation(alert, settings, mock_scenario="normal")
    if plan_res.status != "planned" or not plan_res.plan:
        return plan_res, None
    return plan_res, run_investigation(alert, plan_res.plan, settings, mock_scenario=mock_scenario, faults=faults)


def load_plan(path: str | Path, alert: dict) -> dict:
    """An accepted plan from `plan --out plan.json` or from a planning run record; re-checked against the alert."""
    from soc_agent.tools.planning import plan_problems

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{Path(path).name} holds no accepted plan (expected a JSON object)")
    plan = data.get("plan") if data.get("phase") == "planning" else data
    if not isinstance(plan, dict) or not plan.get("plan_id") or not plan.get("investigation_id"):
        raise ValueError(f"{Path(path).name} holds no accepted plan (use `plan --out` or a planning run record)")
    if plan.get("alert_id") != alert["alert_id"]:
        raise ValueError(f"the plan is for alert {plan.get('alert_id')}, not {alert['alert_id']}")
    import re

    if not re.fullmatch(r"INV-\d{8}-[0-9A-F]{8}", str(plan["investigation_id"])):     # also: no path in a file name
        raise ValueError(f"the plan's investigation_id {str(plan['investigation_id'])[:40]!r} is not INV-YYYYMMDD-XXXXXXXX")
    from soc_agent.config import db_path
    from soc_agent.store import CLOSED, Store

    inv = Store(db_path()).investigation(plan["investigation_id"])
    if inv and inv["status"] == CLOSED:
        raise ValueError(f"investigation {plan['investigation_id']} is closed; run a new investigation")
    if inv and inv["alert_id"] != alert["alert_id"]:
        raise ValueError(f"investigation {plan['investigation_id']} belongs to alert {inv['alert_id']}")
    content = {k: v for k, v in plan.items() if k in ("summary", "hypotheses", "key_questions", "steps",
                                                       "safety_notes", "data_gaps")}
    if issues := plan_problems(content, alert):
        raise ValueError("the plan is not valid: " + "; ".join(issues[:5]))
    return plan


def load_trace(runs_dir: Path, investigation_id: str) -> dict | None:
    """The trace view of a stored investigation record (None if there is none)."""
    path = record_path(runs_dir, investigation_id)
    if not path.is_file():
        return None
    rec = json.loads(path.read_text(encoding="utf-8"))
    return {k: rec.get(k) for k in ("investigation_id", "phase", "plan_id", "alert_id", "status", "error", "llm",
                                    "fault_injection", "exposed_tools", "trace", "evidence_log", "warnings",
                                    "started_at", "finished_at", "duration_ms")}
