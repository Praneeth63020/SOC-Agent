"""HTTP API (FastAPI).   Run: python -m soc_agent serve   ->  http://127.0.0.1:8000/docs

GET  /health
POST /alerts/validate        body: alert JSON (normalized or Wazuh)   -> normalized alert (without raw)
POST /alerts/plan            body: alert JSON; ?provider=nvidia|mock  -> PlanResult (plan + warnings)
POST /alerts/investigate     body: alert JSON; ?provider=nvidia|mock[&scenario=investigate_...]
                                                                       -> {plan, investigation (trace + evidence log)}
POST /alerts/analyze         body: alert JSON; ?provider=nvidia|mock[&scenario=analyze_...][&case=<data scenario>]
                                                                       -> {plan, assessment} (Day 3)
GET  /runs/{investigation_id}                                          -> planning run record (audit)
GET  /runs/{investigation_id}/trace                                    -> tool-call trace of the investigation
GET  /runs/{investigation_id}/assessment                               -> assessment run record (Day 3)

Day 4 (SQLite history / audit trail, incident report, approval workflow):
POST /alerts/run             body: alert JSON; ?provider=nvidia|mock[&scenario=analyze_...|report_...][&case=<data scenario>]
                                                                       -> plan -> assess -> report; pending actions
GET  /investigations[?limit=N]                                         -> investigation history
GET  /investigations/{id}                                              -> investigation, status history, actions
GET  /investigations/{id}/report?format=md|json[&version=N]            -> incident report (current approval status)
GET  /investigations/{id}/audit                                        -> task prompts, every tool call, decisions
GET  /actions[?investigation=ID]                                       -> requested actions and their status
Analyst endpoints (header X-Analyst-Token = ANALYST_API_TOKEN from .env, compared in constant time; 503 if no
token is configured, 401 if it is missing or wrong):
POST /actions/{action_id}/approve     body: {"analyst": "...", "reason": "..."}
POST /actions/{action_id}/reject      body: {"analyst": "...", "reason": "..."}
POST /actions/{action_id}/execute     body: {"analyst": "..."} (optional)  -> SIMULATED execution, approved only
POST /investigations/{id}/close       body: {"analyst": "...", "resolution": "..."}
"""
from __future__ import annotations

import json
import re
import secrets
from importlib.metadata import PackageNotFoundError, version

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from soc_agent import __version__
from soc_agent.alerts import AlertError, normalize
from soc_agent.config import PROJECT_ROOT, ConfigError, load_settings, runs_dir

app = FastAPI(title="Hermes SOC Analyst (Cehpoint prototype)", version=__version__)
SCENARIO_ROOT = PROJECT_ROOT / "data" / "scenarios"
RUN_ID = re.compile(r"^INV-\d{8}-[0-9A-F]{8}$")
ACTION_ID = re.compile(r"^ACT-[0-9A-F]{10}$")


def _failed(detail: dict) -> dict:
    """A 502 body for a failed phase: the raw error plus an actionable hint for known setup problems."""
    from soc_agent.errors import hint_for
    return {**detail, "hint": hint_for(detail.get("error"))}


@app.get("/health")
def health() -> dict:
    try:
        hermes = version("hermes-agent")
    except PackageNotFoundError:
        hermes = None
    return {"status": "ok", "app_version": __version__, "hermes_agent": hermes}


@app.post("/alerts/validate")
def validate_alert(alert: dict = Body(...)) -> dict:
    try:
        a = normalize(alert)
    except AlertError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {k: v for k, v in a.items() if k != "raw"}


@app.post("/alerts/plan")
def plan_alert(alert: dict = Body(...),
               provider: str | None = Query(None, pattern="^(nvidia|mock)$")) -> dict:
    try:
        a = normalize(alert)
    except AlertError as e:
        raise HTTPException(status_code=422, detail=str(e))
    try:
        settings = load_settings(provider)
    except ConfigError as e:
        raise HTTPException(status_code=503, detail=str(e))
    from soc_agent.planner import plan_investigation

    res = plan_investigation(a, settings)          # sync endpoint -> runs in FastAPI's threadpool
    if res.status != "planned":
        raise HTTPException(status_code=502, detail=_failed({"investigation_id": res.investigation_id,
                                                     "status": res.status, "error": res.error}))
    return res.to_dict()


@app.post("/alerts/investigate")
def investigate(alert: dict = Body(...),
                provider: str | None = Query(None, pattern="^(nvidia|mock)$"),
                scenario: str | None = Query(None, pattern="^investigate_(normal|tool_failure|bad_args|fake_ref)$")
                ) -> dict:
    try:
        a = normalize(alert)
    except AlertError as e:
        raise HTTPException(status_code=422, detail=str(e))
    try:
        settings = load_settings(provider)
    except ConfigError as e:
        raise HTTPException(status_code=503, detail=str(e))
    if scenario and not settings.is_mock:
        raise HTTPException(status_code=422, detail="scenario only applies to provider=mock")
    from soc_agent.investigator import investigate_alert

    plan_res, inv = investigate_alert(a, settings, mock_scenario=scenario or "investigate_normal")
    if inv is None:
        raise HTTPException(status_code=502, detail=_failed({"investigation_id": plan_res.investigation_id,
                                                     "phase": "planning", "status": plan_res.status,
                                                     "error": plan_res.error}))
    if inv.status != "completed":
        raise HTTPException(status_code=502, detail=_failed({"investigation_id": inv.investigation_id,
                                                     "phase": "investigation", "status": inv.status,
                                                     "error": inv.error,
                                                     "trace": f"/runs/{inv.investigation_id}/trace"}))
    return {"plan": plan_res.to_dict(), "investigation": inv.to_dict()}


@app.post("/alerts/analyze")
def analyze(alert: dict = Body(...),
            provider: str | None = Query(None, pattern="^(nvidia|mock)$"),
            scenario: str | None = Query(None, pattern="^analyze(_tool_failure|_fake_ref|_overconfident)?$"),
            case: str | None = Query(None, pattern="^[a-z_]{1,40}$",
                                     description="data scenario under data/scenarios/ the tools read")) -> dict:
    import dataclasses

    try:
        a = normalize(alert)
    except AlertError as e:
        raise HTTPException(status_code=422, detail=str(e))
    try:
        settings = load_settings(provider)
    except ConfigError as e:
        raise HTTPException(status_code=503, detail=str(e))
    if scenario and not settings.is_mock:
        raise HTTPException(status_code=422, detail="scenario only applies to provider=mock")
    if case:                                   # a name, never a path: only folders under data/scenarios/
        root = (SCENARIO_ROOT / case).resolve()
        if root.parent != SCENARIO_ROOT.resolve() or not (root / "scenario.json").is_file():
            raise HTTPException(status_code=404, detail=f"no data scenario {case!r}")
        settings = dataclasses.replace(settings, data_dir=root)
    from soc_agent.assessor import analyze_alert

    plan_res, res = analyze_alert(a, settings, mock_scenario=scenario or "analyze")
    if res is None:
        raise HTTPException(status_code=502, detail=_failed({"investigation_id": plan_res.investigation_id,
                                                     "phase": "planning", "status": plan_res.status,
                                                     "error": plan_res.error}))
    if res.status != "completed":
        raise HTTPException(status_code=502, detail=_failed({"investigation_id": res.investigation_id,
                                                     "phase": "assessment", "status": res.status, "error": res.error,
                                                     "assessment": f"/runs/{res.investigation_id}/assessment"}))
    return {"plan": plan_res.to_dict(), "assessment": res.to_dict()}


def _check_id(investigation_id: str) -> None:
    if not RUN_ID.fullmatch(investigation_id):         # strict id format: no path traversal
        raise HTTPException(status_code=400, detail="invalid investigation id (expected INV-YYYYMMDD-XXXXXXXX)")


@app.get("/runs/{investigation_id}/trace")
def get_trace(investigation_id: str) -> dict:
    _check_id(investigation_id)
    from soc_agent.investigator import load_trace

    rec = load_trace(runs_dir().resolve(), investigation_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="no investigation record for this id")
    return rec


@app.get("/runs/{investigation_id}/assessment")
def get_assessment(investigation_id: str) -> dict:
    _check_id(investigation_id)
    from soc_agent.assessor import load_assessment

    rec = load_assessment(runs_dir().resolve(), investigation_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="no assessment record for this id")
    return rec


@app.get("/runs/{investigation_id}")
def get_run(investigation_id: str) -> dict:
    _check_id(investigation_id)
    base = runs_dir().resolve()
    path = (base / f"{investigation_id}.json").resolve()
    if path.parent != base or not path.is_file():
        raise HTTPException(status_code=404, detail="run not found")
    return json.loads(path.read_text(encoding="utf-8"))



# ====================================================================== Day 4
def _store():
    from soc_agent.config import db_path
    from soc_agent.store import Store
    return Store(db_path())


def _scenario_settings(settings, case: str | None):
    import dataclasses

    if not case:
        return settings
    root = (SCENARIO_ROOT / case).resolve()            # a name, never a path
    if root.parent != SCENARIO_ROOT.resolve() or not (root / "scenario.json").is_file():
        raise HTTPException(status_code=404, detail=f"no data scenario {case!r}")
    return dataclasses.replace(settings, data_dir=root)


@app.post("/alerts/run")
def run_alert_endpoint(alert: dict = Body(...),
                       provider: str | None = Query(None, pattern="^(nvidia|mock)$"),
                       scenario: str | None = Query(None, pattern="^(analyze(_tool_failure|_fake_ref|_overconfident)?|"
                                                                  "report(_bypass|_injection)?)$"),
                       case: str | None = Query(None, pattern="^[a-z_]{1,40}$")) -> dict:
    try:
        a = normalize(alert)
    except AlertError as e:
        raise HTTPException(status_code=422, detail=str(e))
    try:
        settings = load_settings(provider)
    except ConfigError as e:
        raise HTTPException(status_code=503, detail=str(e))
    if scenario and not settings.is_mock:
        raise HTTPException(status_code=422, detail="scenario only applies to provider=mock")
    settings = _scenario_settings(settings, case)
    from soc_agent.reporter import run_alert

    sc = scenario or ""
    plan_res, res, rep = run_alert(a, settings, analyze_scenario=sc if sc.startswith("analyze") else "analyze",
                                   report_scenario=sc if sc.startswith("report") else "report")
    inv_id = plan_res.investigation_id
    if res is None or res.status != "completed" or rep is None:
        raise HTTPException(status_code=502, detail=_failed({"investigation_id": inv_id, "status": "failed",
                                                     "error": (res.error if res else plan_res.error),
                                                     "audit": f"/investigations/{inv_id}/audit"}))
    store = _store()
    return {"investigation_id": inv_id, "status": store.investigation(inv_id)["status"],
            "severity": res.assessment["findings"]["severity"], "confidence": res.assessment["findings"]["confidence"],
            "report": {"status": rep.status, "version": rep.report_version, "error": rep.error,
                       "markdown": f"/investigations/{inv_id}/report?format=md",
                       "json": f"/investigations/{inv_id}/report?format=json"},
            "pending_actions": [{k: x[k] for k in ("id", "action_type", "target", "status", "expires_at")}
                                for x in rep.pending_actions],
            "warnings": rep.warnings, "mock": settings.is_mock,
            "data_labels": "SYNTHETIC lab data; MOCK intel (live: false)"}


@app.get("/investigations")
def list_investigations(limit: int = Query(20, ge=1, le=500)) -> list[dict]:
    return _store().investigations(limit)


def _investigation_or_404(store, investigation_id: str) -> dict:
    _check_id(investigation_id)
    inv = store.investigation(investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="no investigation with this id")
    return inv


@app.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: str) -> dict:
    from soc_agent.approvals import list_actions

    store = _store()
    inv = _investigation_or_404(store, investigation_id)
    return {"investigation": inv, "status_history": store.status_history(investigation_id),
            "actions": list_actions(store, investigation_id),
            "report_versions": store.report_versions(investigation_id)}


@app.get("/investigations/{investigation_id}/report")
def get_report(investigation_id: str, format: str = Query("json", pattern="^(md|json)$"),
               version: int | None = Query(None, ge=1)):
    from soc_agent.config import reports_dir
    from soc_agent.report import ReportError, refresh_report

    store = _store()
    _investigation_or_404(store, investigation_id)
    if version is None:
        try:
            refresh_report(store, investigation_id, reports_dir())
        except ReportError:
            pass
    rep = store.report(investigation_id, version)
    if rep is None:
        raise HTTPException(status_code=404, detail="no report for this investigation (or version)")
    if format == "md":
        return PlainTextResponse(rep["markdown"], media_type="text/markdown; charset=utf-8")
    return rep["json"]


@app.get("/investigations/{investigation_id}/audit")
def get_audit(investigation_id: str) -> dict:
    store = _store()
    _investigation_or_404(store, investigation_id)
    return store.export(investigation_id)


@app.get("/actions")
def get_actions(investigation: str | None = Query(None)) -> list[dict]:
    from soc_agent.approvals import list_actions

    if investigation:
        _check_id(investigation)
    return list_actions(_store(), investigation)


# ------------------------------------------------------------ analyst endpoints
def require_analyst_token(x_analyst_token: str | None = Header(None)) -> None:
    """The analyst endpoints need X-Analyst-Token == ANALYST_API_TOKEN (constant-time comparison)."""
    from soc_agent.config import analyst_api_token

    token = analyst_api_token()
    if not token:
        raise HTTPException(status_code=503, detail="analyst endpoints are disabled: ANALYST_API_TOKEN is not set")
    if not x_analyst_token or not secrets.compare_digest(x_analyst_token.encode("utf-8"), token.encode("utf-8")):
        raise HTTPException(status_code=401, detail="missing or invalid X-Analyst-Token")


class Decision(BaseModel):
    model_config = {"extra": "forbid"}
    analyst: str = Field(..., min_length=1, max_length=64)
    reason: str = Field(..., min_length=1, max_length=2000)


class Execution(BaseModel):
    model_config = {"extra": "forbid"}
    analyst: str | None = Field(None, max_length=64)


class Closing(BaseModel):
    model_config = {"extra": "forbid"}
    analyst: str = Field(..., min_length=1, max_length=64)
    resolution: str = Field(..., min_length=1, max_length=2000)


def _check_action_id(action_id: str) -> None:
    if not ACTION_ID.fullmatch(action_id):
        raise HTTPException(status_code=400, detail="invalid action id (expected ACT-XXXXXXXXXX)")


def _refresh(store, investigation_id: str) -> int | None:
    from soc_agent.config import reports_dir
    from soc_agent.report import ReportError, refresh_report

    try:
        saved = refresh_report(store, investigation_id, reports_dir())
    except ReportError:
        return None
    return saved["version"] if saved else None


def _decide(action_id: str, body: Decision, decision: str) -> dict:
    from soc_agent.approvals import ApprovalError, approve, reject

    _check_action_id(action_id)
    store = _store()
    try:
        a = (approve if decision == "approved" else reject)(store, action_id, body.analyst, body.reason)
    except ApprovalError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {"action": a, "report_version": _refresh(store, a["investigation_id"])}


@app.post("/actions/{action_id}/approve", dependencies=[Depends(require_analyst_token)])
def approve_action(action_id: str, body: Decision) -> dict:
    return _decide(action_id, body, "approved")


@app.post("/actions/{action_id}/reject", dependencies=[Depends(require_analyst_token)])
def reject_action(action_id: str, body: Decision) -> dict:
    return _decide(action_id, body, "rejected")


@app.post("/actions/{action_id}/execute", dependencies=[Depends(require_analyst_token)])
def execute_action(action_id: str, body: Execution | None = None) -> dict:
    from soc_agent.approvals import ApprovalError, execute
    from soc_agent.config import simulated_actions_log

    _check_action_id(action_id)
    store = _store()
    try:
        out = execute(store, action_id, simulated_actions_log(), (body.analyst if body else None))
    except ApprovalError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {**out, "simulated": True, "report_version": _refresh(store, out["action"]["investigation_id"])}


@app.post("/investigations/{investigation_id}/close", dependencies=[Depends(require_analyst_token)])
def close_investigation(investigation_id: str, body: Closing) -> dict:
    from soc_agent.approvals import ApprovalError, close

    store = _store()
    _investigation_or_404(store, investigation_id)
    try:
        inv = close(store, investigation_id, body.analyst, body.resolution)
    except ApprovalError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {"investigation": inv, "report_version": _refresh(store, investigation_id)}
