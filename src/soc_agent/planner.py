"""Day 1 workflow: alert in -> Hermes plans -> validated, structured investigation plan out.

The plan only counts if the model submitted it through submit_investigation_plan
and the tool accepted it. If that never happens (or the LLM fails) the result is
status "failed" with the error - a plan is never filled in by the application.

Every run writes a run record runs/<investigation_id>.json: the task (system
prompt + user message), the tools Hermes exposed, every tool call (arguments,
status, result, timestamps), calls Hermes refused, Hermes stats, warnings and
the outcome. (Day 4 turns this into the SQLite-backed audit trail.)
"""
from __future__ import annotations

import contextlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from soc_agent import __version__
from soc_agent.config import Settings
from soc_agent.hermes_runtime import build_agent, exposed_tool_names
from soc_agent.mock_llm import MockLLMServer
from soc_agent.prompts import PLANNER_SYSTEM, planner_task
from soc_agent.tools.base import RunContext, close_run, open_run
from soc_agent.tools.planning import DAY1_TOOLS

HERMES_STATS = ("completed", "failed", "api_calls", "turn_exit_reason", "input_tokens", "output_tokens",
                "final_response", "error")
MOCK_WARNING = "MOCK LLM: this plan was produced by a deterministic script, not by an AI model."


@dataclass
class PlanResult:
    investigation_id: str
    alert_id: str
    status: str                       # "planned" | "failed"
    plan: dict | None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    run_record: str | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_investigation_id() -> str:
    return f"INV-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"


def refused_tool_calls(messages: list, allowed: set[str]) -> list[dict]:
    """Tool calls the model attempted outside our toolset. Hermes refuses them; they never run."""
    replies = {m.get("tool_call_id"): m.get("content") for m in messages or []
               if isinstance(m, dict) and m.get("role") == "tool"}
    refused = []
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function", {}) if isinstance(tc, dict) else {}
            if fn.get("name") and fn["name"] not in allowed:
                refused.append({"tool": fn["name"], "arguments": fn.get("arguments"),
                                "status": "refused_by_hermes", "hermes_reply": replies.get(tc.get("id"))})
    return refused


def plan_investigation(alert: dict, settings: Settings, mock_scenario: str = "normal") -> PlanResult:
    investigation_id = new_investigation_id()
    ctx = RunContext(investigation_id=investigation_id, alert=alert)
    t0 = time.perf_counter()
    task = planner_task(alert)
    record: dict = {
        "investigation_id": investigation_id, "phase": "planning", "app_version": __version__,
        "started_at": _now(), "alert_id": alert["alert_id"], "synthetic_data": bool(alert.get("synthetic")),
        "alert": {k: v for k, v in alert.items() if k != "raw"},
        "llm": {"provider": settings.llm_provider, "model": settings.model, "mock": settings.is_mock,
                "mock_scenario": mock_scenario if settings.is_mock else None},
        "task": {"system_prompt": PLANNER_SYSTEM, "user_message": task,
                 "note": "Hermes prepends its own identity prompt before system_prompt."},
        "exposed_tools": [],
    }
    warnings: list[str] = [MOCK_WARNING] if settings.is_mock else []
    plan = error = None
    open_run(ctx)
    try:
        server_cm = MockLLMServer(mock_scenario) if settings.is_mock else contextlib.nullcontext()
        with server_cm as server:
            agent = build_agent(settings, DAY1_TOOLS, session_id=investigation_id,
                                base_url=server.base_url if server else None)
            record["exposed_tools"] = exposed_tool_names(agent)
            out = agent.run_conversation(task, system_message=PLANNER_SYSTEM, task_id=investigation_id)

        record["hermes"] = {k: out.get(k) for k in HERMES_STATS if k in out}
        record["refused_tool_calls"] = refused_tool_calls(out.get("messages", []), {t.name for t in DAY1_TOOLS})
        if record["refused_tool_calls"]:
            names = sorted({c["tool"] for c in record["refused_tool_calls"]})
            warnings.append(f"Hermes refused {len(record['refused_tool_calls'])} call(s) to tools outside "
                            f"the approved toolset: {names}. Nothing was executed.")
        not_ok = [c for c in ctx.tool_calls if c["status"] != "ok"]
        if not_ok:
            warnings.append(f"{len(not_ok)} tool call(s) were rejected, denied or failed; see the run record.")

        if ctx.plan is None:
            reason = out.get("error") or out.get("final_response") or "no plan was submitted"
            raise RuntimeError(f"Agent did not produce a valid plan: {str(reason)[:300]}")
        if out.get("failed"):
            warnings.append(f"Hermes reported a failure after the plan was accepted: {out.get('error')}")
        plan = {
            "plan_id": f"PLAN-{investigation_id}",
            "investigation_id": investigation_id,
            "alert_id": alert["alert_id"],
            "created_at": _now(),
            "generated_by": {"runtime": "hermes-agent", "provider": settings.llm_provider,
                             "model": settings.model, "mock": settings.is_mock},
            "synthetic_data": bool(alert.get("synthetic")),
            **ctx.plan,
        }
    except Exception as e:     # the API/CLI always gets a structured result, never a fabricated plan
        error = f"{type(e).__name__}: {e}"
    finally:
        close_run(investigation_id)

    duration = round((time.perf_counter() - t0) * 1000, 1)
    status = "planned" if plan else "failed"
    record.update({"finished_at": _now(), "duration_ms": duration, "status": status, "error": error,
                   "warnings": warnings, "tool_calls": ctx.tool_calls, "plan": plan})
    settings.runs_dir.mkdir(parents=True, exist_ok=True)
    path = settings.runs_dir / f"{investigation_id}.json"
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return PlanResult(investigation_id, alert["alert_id"], status, plan, error, warnings, str(path), duration)
