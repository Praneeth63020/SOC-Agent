"""Day 4 workflow: alert -> plan -> investigate + assess -> REPORT, all recorded in the SQLite history.

The report phase is one more Hermes conversation with exactly two tools:
  request_action         [write_internal]  REQUEST block_ip / disable_account / isolate_host (pending, for an analyst)
  submit_report_content  [write_internal]  the executive summary + prioritized recommendations
The disruptive actions themselves are not in the toolset (Hermes refuses them: refused_by_hermes), and nothing
in this module can approve or execute an action; that is soc_agent/approvals.py, used only by the analyst CLI/API.

The agent sees the accepted findings and an evidence index (ref -> tool, entities, short excerpt) of THIS
investigation as data; the refs it may cite are exactly the refs earlier phases' tools returned (RunContext
.evidence_refs is seeded from the database). The report is then assembled by code (report.py), validated
against schemas/incident_report.schema.json and stored as version 1 (later versions after analyst decisions).
"""
from __future__ import annotations

import contextlib
import dataclasses
import json
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from soc_agent import __version__
from soc_agent.config import Settings
from soc_agent.hermes_runtime import build_agent, console_text, exposed_tool_names
from soc_agent.mock_llm import MockLLMServer
from soc_agent.planner import HERMES_STATS, _now, refused_tool_calls, refused_warnings
from soc_agent.prompts import REPORTER_SYSTEM, reporter_task
from soc_agent.report import ReportError, build_report, save_report
from soc_agent.store import Store, save_phase
from soc_agent.tools.actions import REQUEST_ACTION
from soc_agent.tools.base import RunContext, close_run, collect_refs, open_run
from soc_agent.tools.reporting import SUBMIT_REPORT_CONTENT

REPORT_PHASE_TOOLS = [REQUEST_ACTION, SUBMIT_REPORT_CONTENT]
MOCK_WARNING = "MOCK LLM: the report content and action requests were produced by a deterministic script, not by an AI model."
RECORD_SUFFIX = ".report.json"
MAX_INDEX_REFS = 120          # evidence index entries sent to the model (cited + timeline refs first)


@dataclass
class ReportPhaseResult:
    investigation_id: str
    status: str                          # "completed" (report content accepted) | "failed"
    report_version: int | None = None
    report_json_path: str | None = None
    report_md_path: str | None = None
    pending_actions: list[dict] = field(default_factory=list)
    trace: list[dict] = field(default_factory=list)
    refused_tool_calls: list[dict] = field(default_factory=list)
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    run_record: str | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def report_context(store: Store, investigation_id: str, alert: dict, assessment: dict) -> dict:
    """What the agent gets for the report phase (data only): findings, entities, evidence index, open actions."""
    from soc_agent.correlate import condense_timeline

    f = assessment["findings"]
    evidence = store.evidence(investigation_id)
    refs = collect_refs(f) + list(f["severity_evidence_refs"])
    refs += [r for row in condense_timeline(assessment["timeline"]) for r in row["evidence_refs"]]
    refs += [r for fact in assessment["facts"] for r in fact["evidence_refs"]]
    index = {}
    for r in dict.fromkeys(refs):
        if r in evidence and len(index) < MAX_INDEX_REFS:
            ev = evidence[r]
            index[r] = {k: ev[k] for k in ("tool", "event_type", "time", "account", "host", "ips", "excerpt")
                        if ev.get(k) not in (None, [], "")}
    return {
        "investigation_id": investigation_id, "alert_id": alert["alert_id"],
        "alert_entities": alert.get("entities") or {},
        "severity": f["severity"], "confidence": f["confidence"], "severity_rationale": f["severity_rationale"],
        "severity_evidence_refs": f["severity_evidence_refs"],
        "findings": {k: f[k] for k in ("account_and_asset", "timeline", "source_ip_intelligence", "related_events",
                                       "containment", "unknowns", "alternative_explanations", "recommended_next_steps")}
        | {"hypotheses": [{k: h[k] for k in ("id", "status")} for h in f["hypotheses"]],
           "mitre": [{k: m[k] for k in ("technique_id", "name", "evidence_refs")} for m in f["mitre"]]},
        "gaps": [g["statement"] for g in assessment["gaps"]],
        "evidence_index": index,
        "existing_actions": [{k: a[k] for k in ("id", "action_type", "target", "status")}
                             for a in store.actions(investigation_id)],
        "data_labels": "SYNTHETIC lab data; MOCK intel (live: false)",
    }


def run_report_phase(investigation_id: str, settings: Settings, mock_scenario: str = "report") -> ReportPhaseResult:
    """The report conversation for an investigation whose assessment was accepted; then build + store the report."""
    t0 = time.perf_counter()
    store = Store(settings.db_path)
    inv = store.investigation(investigation_id)
    out = store.latest_output(investigation_id, "assess", status="completed") if inv else None
    if not inv or not out or not (out.get("assessment") or {}).get("findings"):
        return ReportPhaseResult(investigation_id, "failed",
                                 error=f"investigation {investigation_id} has no accepted assessment to report on")
    alert, assessment = inv["alert"], out["assessment"]
    names = {t.name for t in REPORT_PHASE_TOOLS}
    ctx = RunContext(investigation_id=investigation_id, alert=alert, plan=out.get("plan"),
                     allowed_tools=frozenset(names), data_dir=settings.data_dir,
                     tool_timeout_s=settings.tool_timeout_s, store=store, phase="report")
    ctx.evidence_index = store.evidence(investigation_id)
    ctx.evidence_refs = {ref: ev["tool"] for ref, ev in ctx.evidence_index.items()}
    ctx.findings = assessment["findings"]
    context = report_context(store, investigation_id, alert, assessment)
    task = reporter_task(investigation_id, alert, context)
    record: dict = {
        "investigation_id": investigation_id, "phase": "report", "app_version": __version__, "started_at": _now(),
        "alert_id": alert["alert_id"], "synthetic_data": bool(alert.get("synthetic")),
        "llm": {"provider": settings.llm_provider, "model": settings.model, "mock": settings.is_mock,
                "mock_scenario": mock_scenario if settings.is_mock else None},
        "task": {"system_prompt": REPORTER_SYSTEM, "user_message": task,
                 "note": "Hermes prepends its own identity prompt before system_prompt."},
        "limits": {"max_iterations": settings.report_max_iterations, "tool_timeout_s": settings.tool_timeout_s},
        "exposed_tools": [],
    }
    warnings: list[str] = [MOCK_WARNING] if settings.is_mock else []
    error, messages = None, []
    open_run(ctx)
    try:
        server_cm = MockLLMServer(mock_scenario) if settings.is_mock else contextlib.nullcontext()
        with server_cm as server:
            agent = build_agent(dataclasses.replace(settings, max_tokens=settings.assessment_max_tokens),
                                REPORT_PHASE_TOOLS, session_id=f"{investigation_id}-report",
                                base_url=server.base_url if server else None,
                                max_iterations=settings.report_max_iterations)
            record["exposed_tools"] = exposed_tool_names(agent)
            res = agent.run_conversation(task, system_message=REPORTER_SYSTEM, task_id=investigation_id)
        messages = res.get("messages", [])
        record["hermes"] = {k: res.get(k) for k in HERMES_STATS if k in res} | {"console": console_text(agent)}
        record["refused_tool_calls"] = refused_tool_calls(messages, names)
        warnings.extend(refused_warnings(record["refused_tool_calls"]))
        if ctx.report_content is None:
            reason = res.get("error") or res.get("final_response") or "no report content was submitted"
            raise RuntimeError(f"Agent did not produce accepted report content: {str(reason)[:300]}")
    except Exception as e:          # the report is still assembled from the assessment, without agent content
        error = f"{type(e).__name__}: {e}"
    finally:
        close_run(investigation_id)

    by_status = defaultdict(list)
    for c in ctx.tool_calls:
        by_status[c["status"]].append(f"#{c['seq']} {c['tool']}")
    for st in ("rejected", "denied", "error", "timeout"):
        if by_status[st]:
            warnings.append(f"{len(by_status[st])} tool call(s) {st}: {', '.join(by_status[st])}.")
    status = "completed" if ctx.report_content is not None and error is None else "failed"
    from soc_agent.investigator import build_trace

    trace = build_trace(ctx.tool_calls, messages)
    record.update({"finished_at": _now(), "status": status, "error": error, "warnings": warnings,
                   "tool_calls": ctx.tool_calls, "trace": trace, "report_content": ctx.report_content})
    settings.runs_dir.mkdir(parents=True, exist_ok=True)
    path = Path(settings.runs_dir) / f"{investigation_id}{RECORD_SUFFIX}"
    save_phase(settings, ctx, "report", record=record, allowed=names, messages=messages, status=status, error=error,
               warnings=warnings, output=ctx.report_content, mock_scenario=mock_scenario if settings.is_mock else None,
               run_record=str(path))
    # JSON export of the run record, written after the database audit (a write problem here never loses the
    # audit); errors="replace" keeps unencodable model text (e.g. a lone surrogate) from crashing the run
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str), encoding="utf-8", errors="replace")
    result = ReportPhaseResult(investigation_id, status, trace=trace,
                               refused_tool_calls=record.get("refused_tool_calls", []), error=error,
                               warnings=warnings, run_record=str(path))
    try:
        saved = save_report(store, build_report(store, investigation_id), settings.reports_dir)
        result.report_version, result.report_json_path, result.report_md_path = (
            saved["version"], saved["json_path"], saved["md_path"])
    except (ReportError, ValueError) as e:
        result.error = (result.error + "; " if result.error else "") + f"report not built: {e}"
        result.status = "failed"
    result.pending_actions = store.actions(investigation_id)
    result.duration_ms = round((time.perf_counter() - t0) * 1000, 1)
    return result


def run_alert(alert: dict, settings: Settings, analyze_scenario: str = "analyze", report_scenario: str = "report",
              faults: dict | None = None):
    """Day 4 `run`: plan -> investigate + assess -> report. Returns (plan, assessment, report phase) results;
    later ones are None if an earlier phase failed."""
    from soc_agent.assessor import analyze_alert

    plan_res, assess_res = analyze_alert(alert, settings, mock_scenario=analyze_scenario, faults=faults)
    if assess_res is None or assess_res.status != "completed":
        return plan_res, assess_res, None
    return plan_res, assess_res, run_report_phase(plan_res.investigation_id, settings, mock_scenario=report_scenario)
