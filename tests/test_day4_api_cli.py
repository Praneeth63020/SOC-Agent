"""Day 4 end to end: CLI run -> report + pending actions -> approve -> execute (simulated) -> close -> audit;
the API mirror and its analyst token."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import soc_agent.api as api
from soc_agent.cli import main
from soc_agent.config import db_path, simulated_actions_log
from soc_agent.store import CLOSED, Store

ROOT = Path(__file__).resolve().parent.parent
ALERT = str(ROOT / "data" / "alerts" / "account_compromise.json")
client = TestClient(api.app)
TOKEN = "test-analyst-token-0123456789"   # dummy test value, not a secret  secret-scan: ignore


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("SOC_HERMES_HOME", str(tmp_path / "hermes"))
    return tmp_path


def test_cli_end_to_end(isolated, capsys):
    assert main(["run", ALERT, "--provider", "mock"]) == 0
    out = capsys.readouterr().out
    st = Store(db_path())
    inv = st.investigations()[0]["id"]
    assert inv in out and "Markdown:" in out and "JSON:" in out and "status Awaiting Approval" in out
    assert "actions approve ACT-" in out and "SYNTHETIC LAB DATA - MOCK INTELLIGENCE" in out
    md_path = Path(out.split("Markdown: ", 1)[1].split()[0])
    assert md_path.is_file() and md_path.parent == isolated / "reports"
    acts = st.actions(inv)
    first, rest = acts[0], acts[1:]

    assert main(["actions", "execute", first["id"]]) == 1                    # not approved yet
    assert "approve it first" in capsys.readouterr().err
    assert main(["actions", "approve", first["id"], "--analyst", "agent", "--reason", "self-approval"]) == 1
    assert main(["actions", "approve", first["id"], "--analyst", "Priya Analyst", "--reason",
                 "Brute-force source, see L12-L64"]) == 0
    assert main(["actions", "execute", first["id"]]) == 0
    out = capsys.readouterr().out
    assert "EXECUTED - SIMULATED" in out and "Report updated: v" in out
    assert main(["actions", "execute", first["id"]]) == 0                    # idempotent
    assert "ALREADY EXECUTED" in capsys.readouterr().out
    assert main(["close", inv, "--analyst", "Priya Analyst", "--resolution", "Contained (simulated block)."]) == 1
    assert "still await a decision" in capsys.readouterr().err
    for a in rest:
        assert main(["actions", "reject", a["id"], "--analyst", "Priya Analyst", "--reason", "Not needed now"]) == 0
    assert main(["close", inv, "--analyst", "Priya Analyst", "--resolution", "Contained (simulated block).",
                 ]) == 0
    capsys.readouterr()
    assert st.investigation(inv)["status"] == CLOSED
    lines = simulated_actions_log().read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["action_id"] == first["id"]

    assert main(["report", inv, "--format", "json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["status"] == CLOSED and rep["resolution"]["closed_by"] == "Priya Analyst"
    assert {p["status"] for p in rep["pending_actions"]} == {"executed", "rejected"}
    assert main(["report", inv]) == 0 and "**Closed** by Priya Analyst" in capsys.readouterr().out
    assert main(["history"]) == 0 and inv in capsys.readouterr().out
    assert main(["audit", inv]) == 0
    audit = capsys.readouterr().out
    for s in ("task system prompt:", "request_action", "submit_report_content", "decision", "SIMULATED",
              "Awaiting Approval -> Under Investigation", "-> Closed"):
        assert s in audit, s
    assert main(["verify-audit"]) == 0 and "OK - every hash chain verifies" in capsys.readouterr().out
    out_file = isolated / "export.json"
    assert main(["export", inv, "--out", str(out_file)]) == 0
    exported = json.loads(out_file.read_text())
    assert exported["investigation"]["id"] == inv and len(exported["decisions"]) == len(acts)
    assert main(["audit", "../../etc/passwd"]) == 2


def test_verify_audit_cli_reports_a_broken_chain(isolated, capsys):
    import sqlite3

    assert main(["run", ALERT, "--provider", "mock"]) == 0
    capsys.readouterr()
    conn = sqlite3.connect(db_path())
    conn.execute("DROP TRIGGER tool_calls_no_update")
    conn.execute("UPDATE tool_calls SET result_summary = 'nothing to see here' WHERE id = 3")
    conn.commit()
    conn.close()
    assert main(["verify-audit"]) == 1
    out = capsys.readouterr().out
    assert "BROKEN at row id 3" in out and "FAILED" in out


def test_run_bypass_scenario_from_the_cli(isolated, capsys):
    assert main(["run", ALERT, "--provider", "mock", "--scenario", "report_bypass"]) == 0
    out = capsys.readouterr().out
    assert out.count("REFUSED_BY_HERMES") == 4 and "REJECTED" in out
    st = Store(db_path())
    inv = st.investigations()[0]["id"]
    assert st.simulated(inv) == [] and st.decisions(inv) == []


# ------------------------------------------------------------------ API
def _run_via_api() -> dict:
    r = client.post("/alerts/run?provider=mock", json=json.loads(Path(ALERT).read_text()))
    assert r.status_code == 200, r.text
    return r.json()


def test_api_read_endpoints(isolated):
    body = _run_via_api()
    inv = body["investigation_id"]
    assert body["status"] == "Awaiting Approval" and len(body["pending_actions"]) == 4 and body["mock"] is True
    assert client.get("/investigations").json()[0]["id"] == inv
    got = client.get(f"/investigations/{inv}").json()
    assert got["investigation"]["status"] == "Awaiting Approval" and len(got["actions"]) == 4
    md = client.get(f"/investigations/{inv}/report?format=md")
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert "SYNTHETIC LAB DATA - MOCK INTELLIGENCE" in md.text
    js = client.get(f"/investigations/{inv}/report?format=json").json()
    assert js["incident_id"] == inv and js["version"] == 1
    audit = client.get(f"/investigations/{inv}/audit").json()
    assert {p["phase"] for p in audit["phases"]} == {"plan", "assess", "report"} and audit["tool_calls"]
    assert client.get("/investigations/INV-1/report").status_code == 400
    assert client.get("/investigations/INV-20991231-ABCDEF12").status_code == 404
    assert client.get(f"/actions?investigation={inv}").status_code == 200


def test_analyst_endpoints_need_a_configured_token(isolated):
    body = _run_via_api()
    aid = body["pending_actions"][0]["id"]
    r = client.post(f"/actions/{aid}/approve", json={"analyst": "Priya", "reason": "ok to block"},
                    headers={"X-Analyst-Token": "anything"})
    assert r.status_code == 503 and "ANALYST_API_TOKEN" in r.json()["detail"]


def test_analyst_token_required_and_compared_in_constant_time(isolated, monkeypatch):
    monkeypatch.setenv("ANALYST_API_TOKEN", TOKEN)
    seen = []
    real = api.secrets.compare_digest
    monkeypatch.setattr(api.secrets, "compare_digest", lambda a, b: seen.append((a, b)) or real(a, b))
    body = _run_via_api()
    inv, aid = body["investigation_id"], body["pending_actions"][0]["id"]
    payload = {"analyst": "Priya", "reason": "ok to block"}
    assert client.post(f"/actions/{aid}/approve", json=payload).status_code == 401
    assert client.post(f"/actions/{aid}/approve", json=payload, headers={"X-Analyst-Token": "wrong"}).status_code == 401
    assert client.post(f"/actions/{aid}/execute", headers={"X-Analyst-Token": TOKEN[:-1]}).status_code == 401
    assert client.post(f"/investigations/{inv}/close", json={"analyst": "Priya", "resolution": "x" * 20},
                       headers={"X-Analyst-Token": "wrong"}).status_code == 401
    assert seen and all(isinstance(a, bytes) for a, _ in seen)              # secrets.compare_digest was used
    st = Store(db_path())
    assert st.decisions(inv) == [] and st.action(aid)["status"] == "pending"

    h = {"X-Analyst-Token": TOKEN}
    assert client.post(f"/actions/{aid}/execute", headers=h).status_code == 409          # not approved
    forged = client.post(f"/actions/{aid}/approve", json=payload | {"approved_by": "agent"}, headers=h)
    assert forged.status_code == 422                                                       # strict body
    assert client.post(f"/actions/{aid}/approve", json={"analyst": "hermes", "reason": "self"},
                       headers=h).status_code == 409
    ok = client.post(f"/actions/{aid}/approve", json=payload, headers=h)
    assert ok.status_code == 200 and ok.json()["action"]["status"] == "approved" and ok.json()["report_version"] == 2
    assert client.post(f"/actions/{aid}/approve", json=payload, headers=h).status_code == 409   # one decision
    ex = client.post(f"/actions/{aid}/execute", headers=h)
    assert ex.status_code == 200 and ex.json()["simulated"] is True and ex.json()["already_executed"] is False
    assert client.post(f"/actions/{aid}/execute", headers=h).json()["already_executed"] is True
    for a in body["pending_actions"][1:]:
        assert client.post(f"/actions/{a['id']}/reject", json={"analyst": "Priya", "reason": "later"},
                           headers=h).status_code == 200
    closed = client.post(f"/investigations/{inv}/close", json={"analyst": "Priya", "resolution": "Contained."},
                         headers=h)
    assert closed.status_code == 200 and closed.json()["investigation"]["status"] == CLOSED
    assert client.post("/actions/not-an-id/approve", json=payload, headers=h).status_code == 400
    assert st.verify_audit()["ok"] is True
