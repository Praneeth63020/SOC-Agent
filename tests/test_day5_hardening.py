"""Day 5 hardening: the defects found in the final review, plus setup errors and the check command.

Each test names the problem it guards against. Everything is offline (mock LLM, temporary databases).
"""
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc_agent.approvals import ApprovalError, approve, check_analyst, execute, expire_overdue, reject
from soc_agent.cli import main
from soc_agent.config import db_path
from soc_agent.errors import hint_for, python_problem
from soc_agent.report import _cell, _para
from soc_agent.store import UNDER_INVESTIGATION, Store

ROOT = Path(__file__).resolve().parent.parent
ALERT = str(ROOT / "data" / "alerts" / "account_compromise.json")


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("SOC_HERMES_HOME", str(tmp_path / "hermes"))
    return tmp_path


@pytest.fixture
def store_with_actions(tmp_path, alert):
    """A database with one investigation and three pending requests (no LLM involved)."""
    st = Store(tmp_path / "soc.db")
    inv = "INV-20261121-0000D005"
    st.ensure_investigation(inv, alert, "mock", "mock-soc-planner", True)
    st.set_status(inv, UNDER_INVESTIGATION, "system", "test")
    acts = [st.add_pending_action(inv, t, target, "reason text", ["wazuh_alerts.jsonl#L64"], "impact", "agent",
                                  "report")
            for t, target in (("block_ip", "203.0.113.77"), ("disable_account", "j.mehta"),
                              ("isolate_host", "fin-app-01"))]
    return st, inv, acts


def _force(st: Store, sql: str, params=()) -> None:
    """Write to the database as an attacker with file access would (outside the application)."""
    conn = sqlite3.connect(st.path)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


# ------------------------------------------------ review finding 1: a rejected action could be executed
def test_execute_needs_an_approved_decision_not_just_the_status_column(store_with_actions, tmp_path):
    st, inv, (a1, a2, a3) = store_with_actions
    reject(st, a1["id"], "Priya Shah", "not needed")
    _force(st, "UPDATE pending_actions SET status = 'approved' WHERE id = ?", (a1["id"],))
    with pytest.raises(ApprovalError, match="no analyst approval in the audit trail"):
        execute(st, a1["id"], tmp_path / "sim.log")
    _force(st, "UPDATE pending_actions SET status = 'approved' WHERE id = ?", (a2["id"],))   # never decided
    with pytest.raises(ApprovalError, match="decision: none"):
        execute(st, a2["id"], tmp_path / "sim.log")
    assert st.simulated(inv) == []
    res = st.verify_audit()
    assert res["ok"] is False and res["tables"]["action_states"]["first_broken"]["id"] == a1["id"]


# ------------------------------------------------ review finding 2: forged phase / report rows went unnoticed
def test_a_phase_row_inserted_outside_the_application_breaks_verify_audit(store_with_actions):
    st, inv, _ = store_with_actions
    st.record_phase(inv, "assess", system_prompt="s", user_message="u", exposed_tools=[], started_at="t0",
                    finished_at="t1", status="completed", hermes=None, error=None, warnings=[], calls=[],
                    output={"assessment": {"findings": {"severity": "critical"}}})
    assert st.verify_audit()["ok"] is True
    _force(st, "INSERT INTO phases (investigation_id, phase, status, output_json) VALUES (?, 'assess', "
               "'completed', ?)", (inv, json.dumps({"assessment": {"findings": {"severity": "low"}}})))
    res = st.verify_audit()
    assert res["ok"] is False and "without a hash" in res["tables"]["phases"]["first_broken"]["problem"]


def test_an_older_database_is_migrated_and_its_unchained_rows_are_accepted_as_a_prefix(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE phases (id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL, "
                 "phase TEXT NOT NULL, task_system_prompt TEXT, task_user_message TEXT, exposed_tools_json TEXT, "
                 "started_at TEXT, finished_at TEXT, status TEXT, hermes_json TEXT, error TEXT, warnings_json TEXT, "
                 "mock_scenario TEXT, output_json TEXT, run_record TEXT)")
    conn.execute("INSERT INTO phases (investigation_id, phase, status) VALUES ('INV-20261120-00000001', 'plan', "
                 "'completed')")
    conn.commit()
    conn.close()
    st = Store(path)
    st.record_phase("INV-20261120-00000001", "assess", system_prompt=None, user_message=None, exposed_tools=[],
                    started_at="a", finished_at="b", status="failed", hermes=None, error="x", warnings=[], calls=[])
    res = st.verify_audit()
    assert res["ok"] is True and res["tables"]["phases"]["unchained_legacy_rows"] == 1


# ------------------------------------------------ review finding 3: expiries left no audit record
def test_every_expiry_is_a_chained_action_event(store_with_actions):
    st, inv, (a1, a2, a3) = store_with_actions
    approve(st, a1["id"], "Priya Shah", "go ahead")
    later = datetime.now(timezone.utc) + timedelta(hours=25)
    assert sorted(expire_overdue(st, inv, now=later)) == sorted(a["id"] for a in (a1, a2, a3))
    events = st.action_events(inv)
    assert sorted((e["action_id"], e["from_status"], e["by"]) for e in events) == sorted([
        (a1["id"], "approved", "system"), (a2["id"], "pending", "system"), (a3["id"], "pending", "system")])
    assert "not executed before it expired" in next(e for e in events if e["action_id"] == a1["id"])["reason"]
    assert st.verify_audit()["ok"] is True
    assert expire_overdue(st, inv, now=later) == []                  # nothing twice
    assert len(st.action_events(inv)) == 3


# ------------------------------------------------ review finding 4 + 5: fault injection / data labels
def test_fault_injection_is_labelled_in_the_run_output_and_the_report(isolated, capsys, monkeypatch):
    monkeypatch.setenv("SOC_TOOL_TIMEOUT_S", "0.3")
    assert main(["run", ALERT, "--provider", "mock", "--fault", "lookup_ip:timeout"]) == 0
    out = capsys.readouterr().out
    assert "*** FAULT INJECTION ACTIVE (testing only): {'lookup_ip': 'timeout'}" in out
    md = Path(out.split("Markdown: ", 1)[1].split()[0]).read_text()
    assert "**FAULT INJECTION ACTIVE (testing only):** lookup\\_ip: timeout" in md or \
           "**FAULT INJECTION ACTIVE (testing only):** lookup_ip: timeout" in md
    rep = json.loads(Path(out.split("JSON:", 1)[1].split()[0]).read_text())
    assert rep["data_labels"]["fault_injection"] == {"lookup_ip": "timeout"}
    assert any(lab.startswith("FAULT INJECTION ACTIVE") for lab in rep["data_labels"]["labels"])


def test_the_evidence_label_follows_the_data_not_the_alert(isolated, capsys, tmp_path):
    raw = json.loads(Path(ALERT).read_text())
    raw["synthetic"] = False
    raw["description"] = "Alert without its own synthetic marker."
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps(raw))
    assert main(["run", str(alert), "--provider", "mock", "--json"]) == 0
    res = json.loads(capsys.readouterr().out)
    rep = json.loads(Path(res["report"]["report_json_path"]).read_text())
    assert rep["data_labels"]["synthetic_data"] is True and rep["data_labels"]["alert_synthetic"] is False
    assert "alert not marked synthetic" in rep["data_labels"]["labels"]
    assert "SYNTHETIC lab data (logs, assets)" in rep["data_labels"]["labels"]


# ------------------------------------------------ review finding 6: Markdown injection into the report
def test_report_text_cannot_inject_links_images_or_emphasis():
    evil = "![x](https://evil.example/b.png) [Approve here](https://evil.example/a) **APPROVED** `code` | cell"
    out = _cell(evil)
    for bad in ("![x](", "[Approve here](", "https://", "**APPROVED**", "`code`", " | "):
        assert bad not in out
    assert "<script>" not in _cell("<script>alert(1)</script>")
    assert _para("# heading").startswith("\\#") and _para("- item").startswith("\\-")


# ------------------------------------------------ review finding 8: names of the agent with digits / prefixes
@pytest.mark.parametrize("name", ["Hermes2", "AgentSmith", "Claude3", "mock_bot", "agent", "SYSTEM", "nvidia-ai"])
def test_names_of_the_agent_are_refused(name):
    with pytest.raises(ApprovalError, match="not a human analyst"):
        check_analyst(name)


@pytest.mark.parametrize("name", ["Priya Shah", "Ai Tanaka", "SOC Lead", "Demo Analyst", "Magenta Lee"])
def test_human_names_are_accepted(name):
    assert check_analyst(name) == name


# ------------------------------------------------ setup errors: actionable hints, no stack traces
@pytest.mark.parametrize("error, needle", [
    ('HTTP 403: {"status":403,"title":"Forbidden","detail":"Authorization failed"}', "NVIDIA_API_KEY"),
    ("HTTP 401: Unauthorized", "NVIDIA_API_KEY"),
    ("HTTP 404: 404 page not found", "NVIDIA_MODEL"),
    ("HTTP 429: Too Many Requests", "Rate limited"),
    ("Connection error.", "network"),
    ("HTTP 503: Service Unavailable", "server error"),
    ("database is locked", "locked"),
])
def test_known_errors_get_an_actionable_hint(error, needle):
    assert needle in hint_for(f"RuntimeError: Agent did not produce a valid plan: {error}")


def test_unknown_errors_get_no_invented_hint():
    assert hint_for("ValueError: something specific") is None and hint_for(None) is None


def test_python_version_check():
    assert python_problem((3, 11)) is None and python_problem((3, 13)) is None
    assert "3.11-3.13" in python_problem((3, 14)) and "3.11-3.13" in python_problem((3, 10))


def test_a_locked_database_is_explained_without_a_traceback(isolated, capsys, monkeypatch):
    def locked(*a, **k):
        raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr("soc_agent.store.Store.investigations", locked)
    assert main(["history"]) == 2
    err = capsys.readouterr().err
    assert "database is locked" in err and "What to do:" in err and "Traceback" not in err


def test_an_unexpected_crash_is_summarized_and_logged(isolated, capsys, monkeypatch):
    def boom(*a, **k):
        raise KeyError("unexpected")
    monkeypatch.setattr("soc_agent.store.Store.investigations", boom)
    assert main(["history"]) == 1
    err = capsys.readouterr().err
    assert "Unexpected error: KeyError" in err and "Traceback" not in err
    log = db_path().parent / "errors.log"
    assert "Traceback" in log.read_text() and "KeyError" in log.read_text()


def test_a_missing_data_dir_is_a_clear_error(isolated, capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_DATA_DIR", str(tmp_path / "nowhere"))
    assert main(["run", ALERT, "--provider", "mock"]) == 2
    assert "does not exist" in capsys.readouterr().err


# ------------------------------------------------ check
def test_check_reports_state_without_showing_secrets(isolated, capsys, monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-" + "x" * 40)          # dummy value  secret-scan: ignore
    monkeypatch.setenv("ANALYST_API_TOKEN", "t" * 32)                  # dummy value  secret-scan: ignore
    assert main(["check"]) == 0
    out = capsys.readouterr().out
    assert "xxxxxxxx" not in out and "tttttttt" not in out
    for needle in ("NVIDIA_API_KEY  set (value not shown)", "analyst token   configured", "database",
                   "(created on the first run)", "scenarios       8 in data/scenarios/", "check: OK"):
        assert needle in out, needle


def test_check_live_explains_a_rejected_key(isolated, capsys, monkeypatch):
    import httpx

    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-" + "y" * 40)          # dummy value  secret-scan: ignore
    monkeypatch.setattr(httpx, "post", lambda *a, **k: httpx.Response(403))
    assert main(["check", "--live"]) == 1
    out = capsys.readouterr().out
    assert "FAILED: HTTP 403" in out and "NVIDIA_API_KEY" in out and "PROBLEMS FOUND: live" in out


# ------------------------------------------------ Hermes console output stays out of the terminal
def test_hermes_console_output_goes_to_the_run_record(isolated, capsys):
    assert main(["plan", ALERT, "--provider", "mock", "--scenario", "http_error"]) == 1
    out = capsys.readouterr().out
    assert "hermes setup" not in out and "💀" not in out
    rec = json.loads(next((isolated / "runs").glob("INV-*.json")).read_text())
    assert "console" in rec["hermes"] and "500" in (rec["hermes"]["console"] or "")


# ------------------------------------------------ NVIDIA rate limits: more Hermes retries than its default 3
def test_hermes_api_retries_come_from_the_settings(mock_settings, monkeypatch):
    from soc_agent.config import load_settings
    from soc_agent.hermes_runtime import build_agent
    from soc_agent.mock_llm import MockLLMServer
    from soc_agent.tools.planning import DAY1_TOOLS

    with MockLLMServer() as m:
        assert build_agent(mock_settings, DAY1_TOOLS, "t1", base_url=m.base_url)._api_max_retries == 6
        monkeypatch.setenv("SOC_API_MAX_RETRIES", "9")
        assert build_agent(load_settings("mock"), DAY1_TOOLS, "t2", base_url=m.base_url)._api_max_retries == 9


# ------------------------------------------------ live run: the model left out "containment" when nothing needed it
def test_a_missing_containment_answer_is_explained_not_waived(alert):
    from soc_agent.tools.assessment import SUBMIT_FINDINGS
    from soc_agent.tools.base import RunContext, call_tool

    ctx = RunContext(investigation_id="INV-20261121-0000D006", alert=alert,
                     allowed_tools=frozenset({SUBMIT_FINDINGS.name}))
    out, entry = call_tool(SUBMIT_FINDINGS, {"severity": "low"}, ctx)
    assert entry["status"] == "rejected"                       # validation is unchanged: still required
    msg = next(p for p in out["problems"] if "'containment' is a required property" in p)
    assert "No containment is indicated" in msg and "evidence_refs" in msg


# ------------------------------------------------ live run: a request contradicting the agent's own findings
def test_request_action_must_match_the_accepted_findings(alert, tmp_path):
    from soc_agent.store import UNDER_INVESTIGATION, Store
    from soc_agent.tools.actions import REQUEST_ACTION
    from soc_agent.tools.base import RunContext, call_tool

    st = Store(tmp_path / "soc.db")
    inv = "INV-20261121-0000D007"
    st.ensure_investigation(inv, alert, "mock", "m", True)
    st.set_status(inv, UNDER_INVESTIGATION, "system", "test")
    ctx = RunContext(investigation_id=inv, alert=alert, allowed_tools=frozenset({REQUEST_ACTION.name}), store=st,
                     phase="report")
    ctx.evidence_index = {"wazuh_alerts.jsonl#L64": {"tool": "search_logs", "account": "j.mehta",
                                                     "host": "fin-app-01", "ips": ["203.0.113.77"]}}
    ctx.evidence_refs = {"wazuh_alerts.jsonl#L64": "search_logs"}
    ctx.findings = {"containment": [{"statement": "No containment is needed: the login came from the usual IP; "
                                                  "do not isolate fin-app-01.",
                                     "evidence_refs": ["wazuh_alerts.jsonl#L64"]},
                                    {"statement": "For analyst consideration (requires approval): disable the "
                                                  "account that logged in.",
                                     "evidence_refs": ["wazuh_alerts.jsonl#L64"]}],
                    "recommended_next_steps": []}
    args = {"action_type": "isolate_host", "target": "fin-app-01", "reason": "Isolate the server now.",
            "evidence_refs": ["wazuh_alerts.jsonl#L64"], "expected_impact": "The server goes offline."}
    out, entry = call_tool(REQUEST_ACTION, args, ctx)
    assert entry["status"] == "rejected" and "do not recommend isolate_host" in json.dumps(out)
    assert st.actions(inv) == []
    ok = {**args, "action_type": "disable_account", "target": "j.mehta", "reason": "The findings recommend it."}
    out, entry = call_tool(REQUEST_ACTION, ok, ctx)                 # recommended via the cited ref's account
    assert entry["status"] == "ok" and st.actions(inv)[0]["target"] == "j.mehta"
