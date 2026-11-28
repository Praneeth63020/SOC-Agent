"""Day 4 analyst path (approvals.py): names, single decision, expiry, simulated + idempotent execution, close."""
import ast
import json
from datetime import timedelta
from pathlib import Path

import pytest

from soc_agent import approvals
from soc_agent.approvals import ApprovalError, approve, check_analyst, close, execute, list_actions, reject
from soc_agent.store import (AWAITING_APPROVAL, CLOSED, UNDER_INVESTIGATION, Store, parse_time)

ROOT = Path(__file__).resolve().parent.parent
ALERT = {"alert_id": "ALERT-T-2", "title": "t", "synthetic": True,
         "entities": {"account": "j.mehta", "host": "fin-app-01", "src_ip": "203.0.113.77"}}
INV = "INV-20261121-0000000B"


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "soc.db")
    s.ensure_investigation(INV, ALERT, "mock", "m", True)
    s.set_status(INV, UNDER_INVESTIGATION, "system", "start")
    return s


def _request(store, action_type="block_ip", target="203.0.113.77"):
    return store.add_pending_action(INV, action_type, target, "reason given", ["wazuh_alerts.jsonl#L64"],
                                    "impact", "agent", "report")


@pytest.mark.parametrize("name", ["", "   ", None, "agent", "Agent", "hermes", "Hermes Agent", "hermes-agent",
                                  "MOCK", "system", "AI", "soc_agent", "SOC", "mock-bot", "1abc", "a" * 80, "x;rm -rf"])
def test_analyst_name_rules(name):
    with pytest.raises(ApprovalError):
        check_analyst(name)


def test_valid_analyst_names():
    assert check_analyst("  Priya Analyst ") == "Priya Analyst"
    assert check_analyst("j.doe") == "j.doe" and check_analyst("O'Brien") == "O'Brien"
    assert check_analyst("SOC Lead") == "SOC Lead" and check_analyst("Ai Tanaka") == "Ai Tanaka"   # real names


def test_agent_cannot_approve_and_reason_required(store):
    a = _request(store)
    with pytest.raises(ApprovalError, match="not a human analyst"):
        approve(store, a["id"], "hermes", "looks fine")
    with pytest.raises(ApprovalError, match="reason"):
        approve(store, a["id"], "Priya", "  ")
    assert store.action(a["id"])["status"] == "pending" and store.decisions(INV) == []


def test_one_decision_per_action(store):
    a = _request(store)
    approve(store, a["id"], "Priya", "evidence L12-L64")
    for fn in (approve, reject):
        with pytest.raises(ApprovalError, match="only one decision"):
            fn(store, a["id"], "Ravi", "second opinion")
    assert [(d["decision"], d["analyst"]) for d in store.decisions(INV)] == [("approved", "Priya")]


def test_status_returns_to_under_investigation_when_nothing_is_pending(store):
    a, b = _request(store), _request(store, "disable_account", "j.mehta")
    assert store.investigation(INV)["status"] == AWAITING_APPROVAL
    approve(store, a["id"], "Priya", "ok to block")
    assert store.investigation(INV)["status"] == AWAITING_APPROVAL       # b still pending
    reject(store, b["id"], "Priya", "user confirmed travel")
    assert store.investigation(INV)["status"] == UNDER_INVESTIGATION
    last = store.status_history(INV)[-1]
    assert last["by"] == "analyst:Priya" and last["from_status"] == AWAITING_APPROVAL


def test_execute_requires_approval(store, tmp_path):
    log = tmp_path / "sim.log"
    a = _request(store)
    with pytest.raises(ApprovalError, match="pending: an analyst must approve it first"):
        execute(store, a["id"], log)
    b = _request(store, "isolate_host", "fin-app-01")
    reject(store, b["id"], "Priya", "too disruptive")
    with pytest.raises(ApprovalError, match="rejected"):
        execute(store, b["id"], log)
    with pytest.raises(ApprovalError, match="no action"):
        execute(store, "ACT-FFFFFFFFFF", log)
    assert store.simulated(INV) == [] and not log.exists()


def test_execute_is_simulated_and_idempotent(store, tmp_path):
    log = tmp_path / "sim.log"
    a = _request(store)
    approve(store, a["id"], "Priya", "block the brute-force source")
    out = execute(store, a["id"], log)
    assert out["already_executed"] is False and out["action"]["status"] == "executed"
    assert out["simulation"]["simulated_effect"].startswith("SIMULATED") and "203.0.113.77" in \
        out["simulation"]["simulated_effect"]
    assert out["simulation"]["executed_by"] == "(not named; approved by Priya)"   # never credited to the approver
    again = execute(store, a["id"], log, analyst="Ravi")
    assert again["already_executed"] is True and again["simulation"]["id"] == out["simulation"]["id"]
    assert len(store.simulated(INV)) == 1
    lines = log.read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["simulated"] is True
    assert store.verify_audit()["ok"] is True


def test_expired_actions_cannot_be_approved_or_executed(store, tmp_path):
    a = _request(store)
    later = parse_time(a["created_at"]) + timedelta(hours=24, seconds=1)
    with pytest.raises(ApprovalError, match="expired"):
        approve(store, a["id"], "Priya", "too late", now=later)
    assert store.action(a["id"])["status"] == "expired"
    b = _request(store, "disable_account", "j.mehta")
    approve(store, b["id"], "Priya", "disable now")
    with pytest.raises(ApprovalError, match="expired"):
        execute(store, b["id"], tmp_path / "sim.log", now=parse_time(b["expires_at"]) + timedelta(seconds=1))
    assert store.action(b["id"])["status"] == "expired" and store.simulated(INV) == []
    assert [x["status"] for x in list_actions(store, INV)] == ["expired", "expired"]


def test_list_actions_marks_overdue_pending_as_expired(store):
    a = _request(store)
    rows = list_actions(store, INV, now=parse_time(a["expires_at"]) + timedelta(minutes=1))
    assert rows[0]["status"] == "expired" and rows[0]["decision"] is None


def test_close_rules(store, tmp_path):
    a = _request(store)
    with pytest.raises(ApprovalError, match="still await a decision"):
        close(store, INV, "Priya", "contained and reviewed")
    approve(store, a["id"], "Priya", "block it")
    with pytest.raises(ApprovalError, match="not a human analyst"):
        close(store, INV, "agent", "contained and reviewed")
    with pytest.raises(ApprovalError, match="resolution"):
        close(store, INV, "Priya", "done")
    inv = close(store, INV, "Priya", "Source blocked; user credentials reset.")
    assert inv["not_executed"] == [a["id"]]                            # approved, never executed: reported
    assert inv["status"] == CLOSED and inv["closed_by"] == "Priya" and inv["resolution"].startswith("Source")
    with pytest.raises(ApprovalError, match="closed"):
        execute(store, a["id"], tmp_path / "sim.log")                  # nothing runs on a closed investigation
    with pytest.raises(ApprovalError, match="already closed"):
        close(store, INV, "Priya", "again, closing twice")
    assert store.status_history(INV)[-1]["to_status"] == CLOSED


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
            out |= {f"{node.module}.{a.name}" for a in node.names}       # from soc_agent import approvals
    return out


def test_tool_layer_never_imports_the_analyst_path():
    """The agent reaches code only through tools; no tool module (nor the agent runtime / phases) imports
    approvals.py, so no tool can approve or execute."""
    agent_side = list((ROOT / "src" / "soc_agent" / "tools").glob("*.py")) + [
        ROOT / "src" / "soc_agent" / f for f in ("hermes_runtime.py", "planner.py", "investigator.py", "assessor.py",
                                                  "reporter.py", "mock_llm.py", "prompts.py")]
    for path in agent_side:
        assert not {m for m in _imports(path) if "approvals" in m}, path
        assert "import_module" not in path.read_text(encoding="utf-8"), path      # no dynamic import either
    assert not hasattr(approvals, "ToolSpec")


def test_no_new_requests_on_a_closed_investigation(store):
    from soc_agent.store import StoreError

    close(store, INV, "Priya", "Nothing to contain here.")
    with pytest.raises(StoreError, match="closed"):
        _request(store)
    assert store.actions(INV) == []


def test_expired_requests_release_awaiting_approval(store):
    a = _request(store)
    assert store.investigation(INV)["status"] == AWAITING_APPROVAL
    list_actions(store, INV, now=parse_time(a["expires_at"]) + timedelta(minutes=1))
    assert store.investigation(INV)["status"] == UNDER_INVESTIGATION
    last = store.status_history(INV)[-1]
    assert last["by"] == "system" and "expired" in last["reason"]
    assert close(store, INV, "Priya", "Requests expired; closed after review.")["status"] == CLOSED


def test_approval_is_bound_to_the_request(store, tmp_path):
    """Changing the request after the decision (even with a plain UPDATE, which pending_actions allows) makes
    execute refuse and verify-audit report it."""
    import sqlite3

    a = _request(store)
    approve(store, a["id"], "Priya", "block the source")
    d = store.decisions(INV)[0]
    assert (d["action_type"], d["target"]) == ("block_ip", "203.0.113.77") and len(d["request_digest"]) == 64
    assert store.verify_audit()["ok"] is True
    conn = sqlite3.connect(store.path)
    conn.execute("UPDATE pending_actions SET action_type = 'isolate_host', target = '10.0.0.5' WHERE id = ?",
                 (a["id"],))
    conn.commit()
    conn.close()
    with pytest.raises(ApprovalError, match="changed after it was approved"):
        execute(store, a["id"], tmp_path / "sim.log", analyst="Priya")
    res = store.verify_audit()
    assert res["ok"] is False and res["tables"]["pending_actions"]["first_broken"]["id"] == a["id"]
    assert store.simulated(INV) == []


def test_execute_by_a_named_analyst(store, tmp_path):
    a = _request(store)
    approve(store, a["id"], "Priya", "block the source")
    assert execute(store, a["id"], tmp_path / "s.log", analyst="Ravi")["simulation"]["executed_by"] == "Ravi"


def test_close_rechecks_inside_the_transaction(store, monkeypatch):
    """A request that lands between close's preparation and its write is still seen: close refuses."""
    real = approvals.expire_overdue

    def racing(*a, **k):
        out = real(*a, **k)
        _request(store)                                   # request_action commits right now
        return out

    monkeypatch.setattr(approvals, "expire_overdue", racing)
    with pytest.raises(ApprovalError, match="still await a decision"):
        close(store, INV, "Priya", "Closing while a request arrives.")
    assert store.investigation(INV)["status"] == AWAITING_APPROVAL


def test_overdue_requests_do_not_block_close_or_new_requests(store):
    a = _request(store)
    with store.tx() as conn:                              # make it overdue
        conn.execute("UPDATE pending_actions SET expires_at = '2000-01-01T00:00:00.000+00:00' WHERE id = ?",
                     (a["id"],))
    b = _request(store)                                   # same type + target: not a duplicate once overdue
    assert b["id"] != a["id"]
    reject(store, b["id"], "Priya", "not needed")
    inv = close(store, INV, "Priya", "Overdue request expired; closed.")
    assert inv["status"] == CLOSED and store.action(a["id"])["status"] == "expired"


def test_database_from_before_the_request_digest_still_verifies(tmp_path):
    """Migration: decisions rows written before action_type / target / request_digest existed keep verifying."""
    import sqlite3

    from soc_agent.store import GENESIS, row_hash

    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, action_id NOT NULL UNIQUE, "
                 "investigation_id NOT NULL, decision NOT NULL, analyst NOT NULL, reason NOT NULL, "
                 "decided_at NOT NULL, prev_hash NOT NULL, row_hash NOT NULL)")
    row = {"action_id": "ACT-000000000F", "investigation_id": INV, "decision": "approved", "analyst": "P",
           "reason": "old", "decided_at": "t", "prev_hash": GENESIS}
    row["row_hash"] = row_hash("decisions", row)
    conn.execute(f"INSERT INTO decisions ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})", list(row.values()))
    conn.commit()
    conn.close()
    st = Store(db)
    assert {"action_type", "target", "request_digest"} <= set(st.decisions()[0])
    assert st.verify_audit()["tables"]["decisions"]["ok"] is True
