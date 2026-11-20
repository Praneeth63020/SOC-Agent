"""HTTP API (FastAPI).   Run: python -m soc_agent serve   ->  http://127.0.0.1:8000/docs

GET  /health
POST /alerts/validate        body: alert JSON (normalized or Wazuh)   -> normalized alert (without raw)
POST /alerts/plan            body: alert JSON; ?provider=nvidia|mock  -> PlanResult (plan + warnings)
GET  /runs/{investigation_id}                                          -> run record (audit)
"""
from __future__ import annotations

import json
import re
from importlib.metadata import PackageNotFoundError, version

from fastapi import Body, FastAPI, HTTPException, Query

from soc_agent import __version__
from soc_agent.alerts import AlertError, normalize
from soc_agent.config import ConfigError, load_settings, runs_dir

app = FastAPI(title="Hermes SOC Analyst (Cehpoint prototype, Day 1)", version=__version__)
RUN_ID = re.compile(r"^INV-\d{8}-[0-9A-F]{8}$")


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
        raise HTTPException(status_code=502, detail={"investigation_id": res.investigation_id,
                                                     "status": res.status, "error": res.error})
    return res.to_dict()


@app.get("/runs/{investigation_id}")
def get_run(investigation_id: str) -> dict:
    if not RUN_ID.fullmatch(investigation_id):         # strict id format: no path traversal
        raise HTTPException(status_code=400, detail="invalid investigation id (expected INV-YYYYMMDD-XXXXXXXX)")
    base = runs_dir().resolve()
    path = (base / f"{investigation_id}.json").resolve()
    if path.parent != base or not path.is_file():
        raise HTTPException(status_code=404, detail="run not found")
    return json.loads(path.read_text(encoding="utf-8"))
