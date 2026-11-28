"""Day 4 store: schema, append-only audit tables, hash chains, status lifecycle, audit ordering."""
import sqlite3

import pytest

from soc_agent.store import (APPEND_ONLY_TABLES, AWAITING_APPROVAL, CLOSED, GENESIS, HASHED_TABLES, OPEN,
                             UNDER_INVESTIGATION, Store, StoreError, audit_sequence, evidence_index, row_hash)

ALERT = {"alert_id": "ALERT-T-1", "title": "t", "synthetic": True, "raw": {"secret": "x"},
         "entities": {"account": "j.mehta", "host": "fin-app-01", "src_ip": "203.0.113.77"}}
INV = "INV-20261121-0000000A"


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "soc.db")
    s.ensure_investigation(INV, ALERT, "mock", "mock-soc-planner", True)
    return s


def _call(seq, tool="search_logs", status="ok", **kw):
    return {"seq": seq, "tool": tool, "permission": "read", "arguments": {"source": "all"}, "status": status,
            "result": {"events": []}, "result_summary": "ok", "evidence_refs": [], "started_at": "t1",
            "finished_at": "t2", "duration_ms": 1.5, **kw}


def _phase(store, calls, phase="assess"):
    return store.record_phase(INV, phase, system_prompt="sys", user_message="user", exposed_tools=["search_logs"],
                              started_at="t0", finished_at="t9", status="completed", hermes={"completed": True},
                              error=None, warnings=[], calls=calls)


def test_schema_created(tmp_path):
    s = Store(tmp_path / "x" / "soc.db")
    names = {r["name"] for r in s.query("SELECT name FROM sqlite_master WHERE type IN ('table', 'trigger')")}
    for t in ("investigations", "phases", "tool_calls", "evidence", "reports", "pending_actions", "decisions",
              "simulated_actions", "status_history"):
        assert t in names
    for t in APPEND_ONLY_TABLES:
        assert f"{t}_no_update" in names and f"{t}_no_delete" in names
    Store(tmp_path / "x" / "soc.db")                       # opening again is idempotent


def test_investigation_created_open_without_raw_payload(store):
    inv = store.investigation(INV)
    assert inv["status"] == OPEN and inv["mock"] is True and inv["synthetic"] is True
    assert "raw" not in inv["alert"]                        # data minimization: the raw payload is never stored
    assert store.ensure_investigation(INV, ALERT, "mock", "m", True) is False
    h = store.status_history(INV)
    assert [(x["from_status"], x["to_status"], x["by"]) for x in h] == [(None, OPEN, "system")]


@pytest.mark.parametrize("table", ["tool_calls", "decisions", "status_history", "simulated_actions", "phases"])
def test_append_only_triggers_block_update_and_delete(store, table):
    _phase(store, [_call(1)])
    with store.tx() as conn:
        store.append_chained(conn, "decisions", {"action_id": "ACT-000000000A", "investigation_id": INV,
                                                 "decision": "approved", "analyst": "A", "reason": "r",
                                                 "decided_at": "t"})
        store.append_chained(conn, "simulated_actions", {
            "action_id": "ACT-000000000A", "investigation_id": INV, "action_type": "block_ip", "target": "x",
            "executed_by": "A", "simulated_effect": "SIMULATED", "executed_at": "t"})
    conn = sqlite3.connect(store.path)
    col = {"tool_calls": "status", "decisions": "decision", "status_history": "to_status",
           "simulated_actions": "target", "phases": "status"}[table]
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute(f"UPDATE {table} SET {col} = 'x'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute(f"DELETE FROM {table}")
    conn.close()


def test_hash_chain_verifies_and_detects_a_tampered_row(store):
    _phase(store, [_call(1), _call(2, tool="lookup_ip"), _call(3, status="rejected")])
    assert store.verify_audit()["ok"] is True
    rows = store.tool_calls(INV)
    assert rows[0]["prev_hash"] == GENESIS and rows[1]["prev_hash"] == rows[0]["row_hash"]
    # an attacker with write access to the file drops the trigger and edits one row
    conn = sqlite3.connect(store.path)
    conn.execute("DROP TRIGGER tool_calls_no_update")
    conn.execute("UPDATE tool_calls SET status = 'ok' WHERE seq = 3")
    conn.commit()
    conn.close()
    res = store.verify_audit()
    assert res["ok"] is False
    broken = res["tables"]["tool_calls"]["first_broken"]
    assert broken["id"] == rows[2]["id"] and "modified" in broken["problem"]
    assert res["tables"]["status_history"]["ok"] is True


def test_hash_chain_detects_a_deleted_row(store):
    _phase(store, [_call(1), _call(2), _call(3)])
    conn = sqlite3.connect(store.path)
    conn.execute("DROP TRIGGER tool_calls_no_delete")
    conn.execute("DELETE FROM tool_calls WHERE seq = 2")
    conn.commit()
    conn.close()
    broken = store.verify_audit()["tables"]["tool_calls"]["first_broken"]
    assert broken and "deleted" in broken["problem"]


def test_row_hash_covers_every_column(store):
    _phase(store, [_call(1)])
    r = store.query("SELECT * FROM tool_calls")[0]
    assert row_hash("tool_calls", r) == r["row_hash"]
    for col in ("reason", "arguments_json", "started_at", "prev_hash", "duration_ms"):
        assert row_hash("tool_calls", {**r, col: "changed"}) != r["row_hash"]
    assert row_hash("decisions", r) != r["row_hash"]       # the table name is part of the hash


def test_status_transitions_recorded_and_enforced(store):
    assert store.set_status(INV, UNDER_INVESTIGATION, "system", "plan phase started")
    assert store.set_status(INV, UNDER_INVESTIGATION, "system", "again") is False         # no-op, not recorded
    store.add_pending_action(INV, "block_ip", "203.0.113.77", "reason x", ["wazuh_alerts.jsonl#L64"],
                             "impact x", "agent", "report")
    assert store.investigation(INV)["status"] == AWAITING_APPROVAL
    with pytest.raises(StoreError, match="not allowed"):
        store.set_status(INV, OPEN, "system", "back")
    with pytest.raises(StoreError, match="only an analyst"):
        store.set_status(INV, CLOSED, "agent", "done")
    store.set_status(INV, CLOSED, "analyst:Priya", "resolved")
    with pytest.raises(StoreError):
        store.set_status(INV, UNDER_INVESTIGATION, "analyst:Priya", "reopen")
    hist = [(h["from_status"], h["to_status"], h["by"]) for h in store.status_history(INV)]
    assert hist == [(None, OPEN, "system"), (OPEN, UNDER_INVESTIGATION, "system"),
                    (UNDER_INVESTIGATION, AWAITING_APPROVAL, "agent"), (AWAITING_APPROVAL, CLOSED, "analyst:Priya")]
    assert all(h["at"] for h in store.status_history(INV))


def test_duplicate_pending_action_refused(store):
    store.set_status(INV, UNDER_INVESTIGATION, "system", "x")
    store.add_pending_action(INV, "block_ip", "203.0.113.77", "r", ["a.json#x"], "i", "agent", "report")
    with pytest.raises(StoreError, match="already requested"):
        store.add_pending_action(INV, "block_ip", "203.0.113.77", "r", ["a.json#x"], "i", "agent", "report")
    store.add_pending_action(INV, "disable_account", "j.mehta", "r", ["a.json#x"], "i", "agent", "report")
    assert len(store.actions(INV, status="pending")) == 2


def test_large_results_are_capped_with_a_flag(store):
    big = {"events": ["x" * 100] * 400}
    _phase(store, [_call(1, result=big)])
    row = store.tool_calls(INV)[0]
    assert row["result_truncated"] is True and row["result"]["_truncated"] is True


def test_audit_sequence_interleaves_refused_calls_with_reasons():
    dispatched = [_call(1, tool="request_action", finished_at="T1"), _call(2, tool="submit_report_content")]
    messages = [
        {"role": "assistant", "content": "[MOCK] Blocking directly.", "tool_calls": [
            {"id": "a", "function": {"name": "block_ip", "arguments": '{"target": "1.2.3.4"}'}}]},
        {"role": "tool", "tool_call_id": "a", "content": "Tool 'block_ip' does not exist."},
        {"role": "assistant", "content": "Requesting.", "tool_calls": [
            {"id": "b", "function": {"name": "request_action", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "b", "content": "{}"},
        {"role": "assistant", "content": "Shell.", "tool_calls": [
            {"id": "c", "function": {"name": "terminal", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c", "content": "Tool 'terminal' does not exist."},
        {"role": "assistant", "content": "Submitting.", "tool_calls": [
            {"id": "d", "function": {"name": "submit_report_content", "arguments": "{}"}}]},
    ]
    out = audit_sequence(dispatched, messages, {"request_action", "submit_report_content"}, ("Error: Invalid JSON",))
    assert [(c["tool"], c["status"]) for c in out] == [
        ("block_ip", "refused_by_hermes"), ("request_action", "ok"), ("terminal", "refused_by_hermes"),
        ("submit_report_content", "ok")]
    assert out[0]["arguments"] == {"target": "1.2.3.4"} and out[0]["reason"] == "[MOCK] Blocking directly."
    assert out[2]["started_at"] == "T1" and out[2]["duration_ms"] is None
    assert out[3]["reason"] == "Submitting."


def test_evidence_index_entities_and_excerpts():
    results = [{"tool": "search_logs", "result": {"events": [
        {"time": "t", "event_type": "account_change", "account": "backup_svc", "host": "fin-app-01",
         "src_ip": None, "dst_ip": "10.20.5.17", "summary": "useradd backup_svc", "evidence_ref": "w.jsonl#L66"}]}},
        {"tool": "get_asset_context", "result": {"kind": "account", "found": True, "evidence_ref": "i.json#accounts/a",
                                                 "record": {"name": "a", "usual_source_ips": ["10.0.0.1"]}}}]
    idx = evidence_index(results)
    assert idx["w.jsonl#L66"]["account"] == "backup_svc" and idx["w.jsonl#L66"]["excerpt"] == "useradd backup_svc"
    assert idx["i.json#accounts/a"]["account"] == "a" and idx["i.json#accounts/a"]["ips"] == ["10.0.0.1"]


def test_every_phase_of_a_run_is_in_the_database(report_run):
    st, inv = report_run.store, report_run.investigation_id
    phases = st.phases(inv)
    assert [p["phase"] for p in phases] == ["plan", "assess", "report"]
    for p in phases:
        assert p["task_system_prompt"].startswith("You are a junior SOC") and p["task_user_message"]
        assert p["exposed_tools"] and p["started_at"] <= p["finished_at"] and p["status"] in ("planned", "completed")
    calls = st.tool_calls(inv)
    assert {c["phase"] for c in calls} == {"plan", "assess", "report"}
    for c in calls:          # the brief: tool used, input, output, status and timestamps
        assert c["tool"] and c["arguments"] is not None and c["result"] is not None and c["status"]
        assert c["started_at"] and c["finished_at"] and c["duration_ms"] is not None
    assert any(c["reason"] for c in calls if c["phase"] == "assess")
    assert st.verify_audit()["ok"] is True
    assert {h["to_status"] for h in st.status_history(inv)} == {OPEN, UNDER_INVESTIGATION, AWAITING_APPROVAL}
    inv_row = st.investigation(inv)
    assert inv_row["severity"] == "critical" and inv_row["provider"] == "mock" and inv_row["mock"] is True
