"""Day 3 workflow: alert -> Day 1 plan -> ONE Hermes conversation that investigates and assesses.

The agent gets get_alert, the four evidence tools, correlate_evidence and submit_findings
(nothing else). It decides which tools to call from the alert and the results (the plan is a
guide), correlates, and submits findings. The findings only count if submit_findings accepts
them (see tools/assessment.py); the application never fills in an assessment itself.

The assessment combines what the agent submitted with what the code computed deterministically
from the same run: timeline, facts, gaps, conflicts, rubric severity/confidence and the
severity check {agent_severity, rubric_severity, agrees}. It is stored in the run record
runs/<investigation_id>.assessment.json (phase "assessment", same investigation_id as the plan).

(The Day 2 `investigate` command and its evidence log are unchanged; this phase does not use
submit_evidence_log: the tool-call trace with the agent's reason per call and the ref-checked
findings take its place, and the agent may skip or add steps.)
"""
from __future__ import annotations

import contextlib
import dataclasses
import json
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from soc_agent import __version__
from soc_agent.config import PROJECT_ROOT, Settings
from soc_agent.correlate import correlate
from soc_agent.hermes_runtime import build_agent, console_text, exposed_tool_names
from soc_agent.investigator import build_trace
from soc_agent.mock_llm import SCENARIO_FAULTS, MockLLMServer
from soc_agent.planner import (HERMES_STATS, PlanResult, _now, plan_investigation, refused_tool_calls,
                               refused_warnings)
from soc_agent.prompts import ASSESSOR_SYSTEM, assessor_task
from soc_agent.schemas import problems, load_schema
from soc_agent.severity import rubric
from soc_agent.tools.assessment import ASSESSMENT_TOOLS, MAX_FINDINGS_ATTEMPTS
from soc_agent.tools.base import RunContext, close_run, open_run
from soc_agent.tools.evidence import EVIDENCE_TOOLS, data_dir_synthetic
from soc_agent.tools.planning import GET_ALERT

ASSESSMENT_PHASE_TOOLS = [GET_ALERT, *EVIDENCE_TOOLS, *ASSESSMENT_TOOLS]
MOCK_WARNING = "MOCK LLM: these findings were produced by a deterministic script, not by an AI model."
RECORD_SUFFIX = ".assessment.json"


@dataclass
class AssessmentResult:
    investigation_id: str
    alert_id: str
    plan_id: str | None
    status: str                         # "completed" (findings accepted) | "failed"
    assessment: dict | None
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


def _rel(p: Path) -> str:
    try:
        return str(Path(p).resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(p)


def build_assessment(ctx: RunContext, settings: Settings, plan: dict, trace: list[dict], status: str) -> dict:
    """The assessment record (schemas/assessment.schema.json). The correlation and rubric are the ones the
    accepted findings were checked against; without accepted findings they are computed on the final run state
    so the human still sees the evidence, and findings is null."""
    if ctx.findings_check:
        corr, rub, check = (ctx.findings_check["correlation"], ctx.findings_check["rubric"],
                            ctx.findings_check["severity_check"])
    else:
        corr = correlate(ctx.alert, ctx.evidence_results, ctx.tool_calls)
        rub, check = rubric(corr), None
    return {
        "investigation_id": ctx.investigation_id,
        "alert_id": ctx.alert["alert_id"],
        "plan_id": plan.get("plan_id"),
        "status": status,
        "provenance": {
            "runtime": "hermes-agent", "provider": settings.llm_provider, "model": settings.model,
            "mock": settings.is_mock, "synthetic_data": bool(ctx.alert.get("synthetic")),
            "data_synthetic": data_dir_synthetic(settings.data_dir),
            "intel": "MOCK intel feed / MOCK CVE database (live: false)", "data_dir": _rel(settings.data_dir),
            "fault_injection": dict(ctx.faults), "generated_at": _now(), "app_version": __version__,
            "correlation": "deterministic (correlate.py), from this run's tool results only",
            "rubric": "deterministic (severity.py, docs/severity.md)",
        },
        "findings": ctx.findings,
        "severity_check": check,
        "rubric": rub,
        "timeline": corr["timeline"],
        "facts": corr["facts"],
        "gaps": corr["gaps"],
        "conflicts": corr["conflicts"],
        "sources": corr["sources"],
        "notes": corr["notes"],
        "tool_calls": [{k: t.get(k) for k in ("seq", "tool", "status", "arguments", "summary", "reason",
                                              "fault_injected")} | {"evidence_refs_returned": len(t["evidence_refs"])}
                       for t in trace],
    }


def run_assessment(alert: dict, plan: dict, settings: Settings, mock_scenario: str = "analyze",
                   faults: dict | None = None) -> AssessmentResult:
    """Investigate + assess `alert` with the accepted `plan` in one Hermes conversation."""
    investigation_id = plan["investigation_id"]
    names = {t.name for t in ASSESSMENT_PHASE_TOOLS}
    faults = {**settings.faults, **(SCENARIO_FAULTS.get(mock_scenario, {}) if settings.is_mock else {}),
              **(faults or {})}
    ctx = RunContext(investigation_id=investigation_id, alert=alert, plan=plan, allowed_tools=frozenset(names),
                     data_dir=settings.data_dir, tool_timeout_s=settings.tool_timeout_s, faults=faults)
    t0 = time.perf_counter()
    task = assessor_task(alert, plan)
    record: dict = {
        "investigation_id": investigation_id, "phase": "assessment", "plan_id": plan.get("plan_id"),
        "planning_record": f"{investigation_id}.json", "app_version": __version__, "started_at": _now(),
        "alert_id": alert["alert_id"], "synthetic_data": bool(alert.get("synthetic")),
        "alert": {k: v for k, v in alert.items() if k != "raw"}, "plan": plan,
        "llm": {"provider": settings.llm_provider, "model": settings.model, "mock": settings.is_mock,
                "mock_scenario": mock_scenario if settings.is_mock else None},
        "task": {"system_prompt": ASSESSOR_SYSTEM, "user_message": task,
                 "note": "Hermes prepends its own identity prompt before system_prompt."},
        "limits": {"max_iterations": settings.assessment_max_iterations, "max_tokens": settings.assessment_max_tokens,
                   "tool_timeout_s": settings.tool_timeout_s,
                   "max_findings_attempts": MAX_FINDINGS_ATTEMPTS},
        "data_dir": _rel(settings.data_dir), "fault_injection": faults, "exposed_tools": [],
    }
    warnings: list[str] = [MOCK_WARNING] if settings.is_mock else []
    if faults:
        warnings.append(f"FAULT INJECTION ACTIVE (testing only): {faults}")
    error, messages = None, []
    from soc_agent.store import save_phase, start_phase

    store = start_phase(settings, investigation_id, alert, "assess")
    open_run(ctx)
    try:
        if unknown := sorted(set(faults) - names):
            raise ValueError(f"Fault injection names unknown tool(s) {unknown}; tools: {sorted(names)}")
        server_cm = MockLLMServer(mock_scenario) if settings.is_mock else contextlib.nullcontext()
        with server_cm as server:
            agent = build_agent(dataclasses.replace(settings, max_tokens=settings.assessment_max_tokens),
                                ASSESSMENT_PHASE_TOOLS, session_id=f"{investigation_id}-assessment",
                                base_url=server.base_url if server else None,
                                max_iterations=settings.assessment_max_iterations)
            record["exposed_tools"] = exposed_tool_names(agent)
            out = agent.run_conversation(task, system_message=ASSESSOR_SYSTEM, task_id=investigation_id)
        messages = out.get("messages", [])
        record["hermes"] = {k: out.get(k) for k in HERMES_STATS if k in out} | {"console": console_text(agent)}
        record["refused_tool_calls"] = refused_tool_calls(messages, names)
        warnings.extend(refused_warnings(record["refused_tool_calls"]))
        if ctx.findings is None:
            reason = out.get("error") or out.get("final_response") or "no findings were submitted"
            raise RuntimeError(f"Agent did not produce accepted findings: {str(reason)[:300]}")
        if out.get("failed"):
            warnings.append(f"Hermes reported a failure after the findings were accepted: {out.get('error')}")
    except Exception as e:      # always a structured result; findings are never filled in by the application
        error = f"{type(e).__name__}: {e}"
    finally:
        close_run(investigation_id)

    by_status = defaultdict(list)
    for c in ctx.tool_calls:
        by_status[c["status"]].append(f"#{c['seq']} {c['tool']}")
    for st in ("timeout", "error", "rejected", "denied"):
        if by_status[st]:
            warnings.append(f"{len(by_status[st])} tool call(s) {st}: {', '.join(by_status[st])}.")
    status = "completed" if ctx.findings is not None and error is None else "failed"
    trace = build_trace(ctx.tool_calls, messages)
    assessment = build_assessment(ctx, settings, plan, trace, status)
    check = assessment["severity_check"]
    if check and not check["agrees"]:
        warnings.append(f"Agent severity {check['agent_severity']} differs from the rubric ({check['rubric_severity']})"
                        + ("; accepted after one rubric hint without addressing the rubric."
                           if check.get("accepted_after_rubric_hint") else "; the rationale addresses the rubric."))
    if assessment["gaps"]:
        warnings.append(f"Evidence is incomplete: {len(assessment['gaps'])} gap(s): "
                        + "; ".join(g["id"] for g in assessment["gaps"]) + ".")
    if issues := problems(assessment, load_schema("assessment"), limit=5):
        warnings.append("Assessment record does not match schemas/assessment.schema.json: " + "; ".join(issues))

    duration = round((time.perf_counter() - t0) * 1000, 1)
    record.update({"finished_at": _now(), "duration_ms": duration, "status": status, "error": error,
                   "warnings": warnings, "tool_calls": ctx.tool_calls, "trace": trace,
                   "evidence_refs_returned": len(ctx.evidence_refs), "assessment": assessment})
    settings.runs_dir.mkdir(parents=True, exist_ok=True)
    path = record_path(settings.runs_dir, investigation_id)
    if path.exists():           # a re-run with the same plan: keep the earlier record (audit), never overwrite it
        stamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        path.rename(path.with_name(f"{investigation_id}.assessment.{stamp}.json"))
    # phase "assess" = the Day 3 conversation (it investigates AND assesses); the assessment is its output
    save_phase(settings, ctx, "assess", record=record, allowed=names, messages=messages, status=status, error=error,
               warnings=warnings, output={"plan": plan, "assessment": assessment},
               mock_scenario=mock_scenario if settings.is_mock else None, run_record=str(path))
    # JSON export of the run record, written after the database audit (a write problem here never loses the
    # audit); errors="replace" keeps unencodable model text (e.g. a lone surrogate) from crashing the run
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str), encoding="utf-8", errors="replace")
    if ctx.findings:
        store.update_investigation(investigation_id, severity=ctx.findings["severity"],
                                   confidence=ctx.findings["confidence"])
    return AssessmentResult(investigation_id, alert["alert_id"], plan.get("plan_id"), status, assessment, trace,
                            error, warnings, faults, str(path), duration)


def analyze_alert(alert: dict, settings: Settings, mock_scenario: str = "analyze",
                  faults: dict | None = None) -> tuple[PlanResult, AssessmentResult | None]:
    """Day 1 plan, then the Day 3 investigate + assess conversation (only if a plan was accepted)."""
    plan_res = plan_investigation(alert, settings, mock_scenario="normal")
    if plan_res.status != "planned" or not plan_res.plan:
        return plan_res, None
    return plan_res, run_assessment(alert, plan_res.plan, settings, mock_scenario=mock_scenario, faults=faults)


def load_assessment(runs_dir: Path, investigation_id: str) -> dict | None:
    path = record_path(runs_dir, investigation_id)
    if not path.is_file():
        return None
    rec = json.loads(path.read_text(encoding="utf-8"))
    return {k: rec.get(k) for k in ("investigation_id", "phase", "plan_id", "alert_id", "status", "error", "llm",
                                    "fault_injection", "exposed_tools", "trace", "assessment", "warnings",
                                    "started_at", "finished_at", "duration_ms")}
