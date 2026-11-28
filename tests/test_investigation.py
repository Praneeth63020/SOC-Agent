"""Day 2 investigation phase end to end through the real Hermes runtime, driven by the offline mock LLM."""
import dataclasses
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from soc_agent.investigator import INVESTIGATION_TOOLS, MOCK_WARNING, investigate_alert, run_investigation
from soc_agent.mock_llm import FAKE_REF, INVESTIGATION_FINAL_REPLY, build_mock_plan
from soc_agent.planner import plan_investigation
from soc_agent.schemas import load_schema, problems
from soc_agent.tools.base import RunContext, call_tool
from soc_agent.tools.evidence import LOOKUP_IP, SEARCH_LOGS
from soc_agent.tools.investigation import MAX_LOG_ATTEMPTS, SUBMIT_EVIDENCE_LOG

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = {"search_logs", "lookup_ip", "search_cve", "get_asset_context"}


def investigate(alert, settings, scenario="investigate_normal", **kw):
    plan_res, inv = investigate_alert(alert, settings, mock_scenario=scenario, **kw)
    assert plan_res.status == "planned", plan_res.error
    return plan_res, inv, json.loads(Path(inv.run_record).read_text())


def calls(record, tools=EVIDENCE):
    return [(c["tool"], c["status"]) for c in record["tool_calls"] if c["tool"] in tools]


# ---------------------------------------------------------------------------- normal
def test_normal_investigation_runs_the_evidence_tools(alert, mock_settings):
    plan_res, inv, rec = investigate(alert, mock_settings)
    assert inv.status == "completed" and inv.error is None and MOCK_WARNING in inv.warnings
    assert calls(rec) == [("search_logs", "ok"), ("search_logs", "ok"), ("lookup_ip", "ok"),
                          ("get_asset_context", "ok"), ("search_logs", "ok"), ("search_cve", "ok")]
    assert len(calls(rec)) >= 3
    # linked to the plan, same record format, phase "investigation"
    assert rec["phase"] == "investigation" and rec["investigation_id"] == plan_res.investigation_id
    assert rec["plan_id"] == plan_res.plan["plan_id"] == inv.plan_id and rec["plan"] == plan_res.plan
    assert Path(plan_res.run_record).name == rec["planning_record"]
    assert rec["exposed_tools"] == sorted(t.name for t in INVESTIGATION_TOOLS)
    assert rec["hermes"]["completed"] is True and rec["hermes"]["final_response"] == INVESTIGATION_FINAL_REPLY
    assert rec["task"]["system_prompt"] and "No severity" in rec["task"]["user_message"]
    assert rec["refused_tool_calls"] == [] and rec["fault_injection"] == {}


def test_trace_is_stored_with_reasons_and_refs(alert, mock_settings):
    _, inv, rec = investigate(alert, mock_settings)
    assert rec["trace"] == inv.trace and len(rec["trace"]) == len(rec["tool_calls"])
    for t in rec["trace"]:
        assert set(t) == {"seq", "tool", "arguments", "status", "duration_ms", "summary", "evidence_refs",
                          "fault_injected", "reason"}
        assert t["reason"] and t["reason"].startswith("[MOCK]")         # why each call was made
    first = rec["trace"][0]
    assert first["tool"] == "search_logs" and first["reason"].startswith("[MOCK] Step 1:")
    assert first["summary"].startswith("51 matched") and len(first["evidence_refs"]) == 51
    assert rec["trace"][2]["summary"].startswith("203.0.113.77: malicious")
    # the search_cve version came from get_asset_context's result
    assert rec["trace"][5]["arguments"] == {"product": "openssh", "version": "8.9p1"}


def test_evidence_log_cites_only_refs_returned_in_the_run(alert, mock_settings):
    _, inv, rec = investigate(alert, mock_settings)
    log = inv.evidence_log
    assert problems(log, load_schema("evidence_log")) == [] and rec["evidence_log"] == log
    returned = {r for c in rec["tool_calls"] for r in c["evidence_refs"]}
    cited = [r for e in log["executed_steps"] for r in e["evidence_refs"]]
    assert cited and set(cited) <= returned
    assert [e["step"] for e in log["executed_steps"]] == [1, 2, 3, 4, 5, 6]
    assert all(e["outcome"] == "found" for e in log["executed_steps"])
    assert log["skipped_steps"] == [{"step": 7, "tool": "analyst_review", "reason": log["skipped_steps"][0]["reason"]}]
    text = json.dumps(log).lower()
    for word in ("severity", "verdict", "recommend", "compromised"):        # no conclusions on Day 2
        assert word not in text


# ----------------------------------------------------------------------- failures
def test_tool_failure_is_recorded_and_nothing_is_invented(alert, mock_settings):
    fast = dataclasses.replace(mock_settings, tool_timeout_s=0.3)
    _, inv, rec = investigate(alert, fast, "investigate_tool_failure")
    assert inv.status == "completed" and inv.faults == {"lookup_ip": "timeout"}
    assert ("lookup_ip", "timeout") in calls(rec)
    lookup = next(c for c in rec["tool_calls"] if c["tool"] == "lookup_ip")
    assert lookup["result"] == {"error": lookup["result"]["error"], "retryable": True}      # no data
    assert lookup["fault_injected"] == "timeout" and lookup["evidence_refs"] == []
    step3 = next(e for e in inv.evidence_log["executed_steps"] if e["step"] == 3)
    assert step3 == {"step": 3, "tool": "lookup_ip", "reason": step3["reason"], "outcome": "failed", "evidence_refs": []}
    assert "ip_reputation" not in json.dumps(inv.evidence_log)                  # no intel was cited
    assert any("FAULT INJECTION ACTIVE" in w for w in inv.warnings)
    assert any("step(s) [3] failed and returned no data" in w for w in inv.warnings)
    assert rec["fault_injection"] == {"lookup_ip": "timeout"}


def test_invalid_tool_arguments_are_rejected_then_corrected(alert, mock_settings):
    _, inv, rec = investigate(alert, mock_settings, "investigate_bad_args")
    first = rec["tool_calls"][0]
    assert first["tool"] == "search_logs" and first["status"] == "rejected"
    assert "source" not in first["arguments"] and first["arguments"]["event_type"] == "authentication"
    text = " ".join(first["result"]["problems"])
    assert "'source' is a required property" in text and "'authentication' is not one of" in text
    assert rec["tool_calls"][1]["tool"] == "search_logs" and rec["tool_calls"][1]["status"] == "ok"
    assert inv.status == "completed" and inv.evidence_log["executed_steps"][0]["outcome"] == "found"


def test_fake_evidence_ref_is_rejected_then_fixed(alert, mock_settings):
    _, inv, rec = investigate(alert, mock_settings, "investigate_fake_ref")
    submits = [c for c in rec["tool_calls"] if c["tool"] == "submit_evidence_log"]
    assert [c["status"] for c in submits] == ["rejected", "ok"]
    assert FAKE_REF in json.dumps(submits[0]["arguments"])
    assert submits[0]["result"]["problems"] == [
        f"executed step 1: evidence_ref '{FAKE_REF}' was not returned by any tool in this run"]
    assert inv.status == "completed" and FAKE_REF not in json.dumps(inv.evidence_log)


def test_unknown_fault_target_fails_clearly(alert, mock_settings):
    plan = plan_investigation(alert, mock_settings).plan
    inv = run_investigation(alert, plan, mock_settings, faults={"block_ip": "error"})
    assert inv.status == "failed" and "unknown tool(s) ['block_ip']" in inv.error and inv.evidence_log is None


def test_llm_outage_during_investigation_fails_safely(alert, mock_settings):
    plan = plan_investigation(alert, mock_settings).plan
    inv = run_investigation(alert, plan, mock_settings, mock_scenario="http_error")
    assert inv.status == "failed" and inv.evidence_log is None and inv.trace == []
    rec = json.loads(Path(inv.run_record).read_text())
    assert rec["status"] == "failed" and rec["evidence_log"] is None


# ------------------------------------------------- phase isolation (process-global registry)
def test_planning_after_investigation_still_sees_only_planning_tools(alert, mock_settings):
    investigate(alert, mock_settings)                 # registers the evidence tools in toolset "soc"
    res = plan_investigation(alert, mock_settings)
    rec = json.loads(Path(res.run_record).read_text())
    assert rec["exposed_tools"] == ["get_alert", "submit_investigation_plan"] and res.status == "planned"


# ------------------------------------------------------------- evidence log rules (direct)
@pytest.fixture
def evctx(alert):
    """A run where search_logs and get_asset_context succeeded and lookup_ip failed."""
    plan = build_mock_plan(alert)
    ctx = RunContext("INV-TEST-EVLOG", alert, plan=plan, faults={"lookup_ip": "error"})
    call_tool(SEARCH_LOGS, {"source": "wazuh", "account": "a.rao"}, ctx)
    call_tool(LOOKUP_IP, {"ip": "203.0.113.77"}, ctx)
    return ctx


def _log(**changes):
    executed = [
        {"step": 1, "tool": "search_logs", "reason": "Confirm the failures.", "outcome": "found",
         "evidence_refs": ["wazuh_alerts.jsonl#L9"]},
        {"step": 3, "tool": "lookup_ip", "reason": "Check intelligence.", "outcome": "failed", "evidence_refs": []},
    ]
    skipped = [{"step": n, "tool": t, "reason": "Not run in this unit test."}
               for n, t in ((2, "search_logs"), (4, "get_asset_context"), (5, "search_logs"), (6, "search_cve"),
                            (7, "analyst_review"))]
    log = {"executed_steps": executed, "skipped_steps": skipped}
    for fn in changes.values():
        fn(log)
    return log


def submit(ctx, log):
    out, entry = call_tool(SUBMIT_EVIDENCE_LOG, log, ctx)
    return out, entry["status"]


def test_consistent_evidence_log_is_accepted_once(evctx):
    out, status = submit(evctx, _log())
    assert status == "ok" and out["accepted"] is True and evctx.evidence_log == _log()
    out, status = submit(evctx, _log())
    assert status == "rejected" and "already accepted" in out["error"]


@pytest.mark.parametrize("change, needle", [
    (lambda l: l["executed_steps"][0]["evidence_refs"].append("wazuh_alerts.jsonl#L12"),
     "'wazuh_alerts.jsonl#L12' was not returned by any tool in this run"),
    (lambda l: l["executed_steps"][0].update(evidence_refs=[]), "outcome found needs at least one evidence_ref"),
    (lambda l: l["executed_steps"][1].update(outcome="found", evidence_refs=["ip_reputation.json#203.0.113.77"]),
     "was not returned by any tool"),
    (lambda l: l["executed_steps"][1].update(outcome="none"), "no lookup_ip call succeeded"),
    (lambda l: l["executed_steps"][0].update(outcome="failed", evidence_refs=[]), "every search_logs call succeeded"),
    (lambda l: l["executed_steps"][0].update(outcome="none"), "outcome none must not cite evidence_refs"),
    (lambda l: l["executed_steps"][0].update(tool="search_cve"), "the plan uses search_logs for step 1"),
    (lambda l: l["skipped_steps"].pop(0), "plan step 2 (search_logs) is missing"),
    (lambda l: l["skipped_steps"].append({"step": 1, "tool": "search_logs", "reason": "twice"}),
     "step 1 is listed more than once"),
    (lambda l: l["skipped_steps"].append({"step": 9, "tool": "search_logs", "reason": "no such step"}),
     "the plan has no step 9"),
    (lambda l: l["skipped_steps"].pop() and l["executed_steps"].append(
        {"step": 7, "tool": "analyst_review", "reason": "x" * 10, "outcome": "none", "evidence_refs": []}),
     "'analyst_review' is not one of"),
    (lambda l: l.update(verdict="malicious"), "'verdict' was unexpected"),
    (lambda l: l["executed_steps"][0].update(severity="high"), "'severity' was unexpected"),
    (lambda l: l["executed_steps"][0].update(evidence_refs=["wazuh_alerts.jsonl#L9"] * 21), "is too long"),
    (lambda l: l["skipped_steps"][0].update(outcome="skipped"), "'outcome' was unexpected"),
])
def test_inconsistent_evidence_logs_are_rejected(evctx, change, needle):
    out, status = submit(evctx, _log(c=change))
    assert status == "rejected" and evctx.evidence_log is None
    assert needle in json.dumps(out), out


def test_ref_from_another_tool_is_rejected(evctx):
    call_tool(LOOKUP_IP, {"ip": "10.20.1.45"}, evctx)       # internal: ok but returns no ref
    evctx.faults = {}
    call_tool(LOOKUP_IP, {"ip": "203.0.113.77"}, evctx)     # now succeeds and returns the intel ref
    log = _log()
    log["executed_steps"][0]["evidence_refs"].append("ip_reputation.json#203.0.113.77")
    out, status = submit(evctx, log)
    assert status == "rejected" and "was returned by lookup_ip, not by search_logs" in json.dumps(out)


def test_evidence_log_attempts_are_limited(evctx):
    bad = _log(c=lambda l: l["executed_steps"][0].update(evidence_refs=[]))
    for _ in range(MAX_LOG_ATTEMPTS):
        assert submit(evctx, bad)[1] == "rejected"
    out, status = submit(evctx, _log())
    assert status == "rejected" and "Too many evidence log submissions" in out["error"]


def test_submit_schema_is_simplified_for_the_model_only():
    sent = SUBMIT_EVIDENCE_LOG.hermes_schema()["parameters"]
    assert '"pattern"' not in json.dumps(sent) and '"enum"' in json.dumps(sent)
    assert '"pattern"' in json.dumps(SUBMIT_EVIDENCE_LOG.parameters)
    # top-level arrays, not one nested object argument (a live model sent that as a malformed string)
    assert sent["required"] == ["executed_steps", "skipped_steps"]
    assert sent["properties"]["executed_steps"]["type"] == "array"
    assert sent["properties"]["executed_steps"]["items"]["properties"]["evidence_refs"]["maxItems"] == 20


def test_steps_sent_as_a_json_string_are_explained(evctx):
    out, status = submit(evctx, {"executed_steps": json.dumps(_log()["executed_steps"])[:-2], "skipped_steps": []})
    assert status == "rejected" and evctx.evidence_log is None
    assert out["problems"][0].startswith("executed_steps: must be a JSON array, not a string")


# --------------------------------------------------------------------------------- CLI
@pytest.mark.parametrize("argv, code, needles", [
    (["investigate", "data/alerts/account_compromise.json", "--provider", "mock"], 0,
     ["Tool-call trace (7 call(s))", "COMPLETED", "why:  [MOCK] Step 3", "refs: 1 returned: ip_reputation.json#",
      "SKIPPED", "MOCK SCRIPT - NOT AN AI MODEL"]),
    (["investigate", "data/alerts/account_compromise.json", "--provider", "mock", "--scenario",
      "investigate_fake_ref"], 0, ["submit_evidence_log  REJECTED"]),
    (["investigate", "data/alerts/account_compromise.json", "--provider", "mock", "--fault", "search_cve:error"], 0,
     ["FAULT INJECTION ACTIVE", "search_cve           ERROR", "[search_cve] FAILED"]),
    (["investigate", "data/alerts/account_compromise.json", "--provider", "mock", "--fault", "x"], 2, ["Bad fault"]),
    (["investigate", "data/alerts/account_compromise.json", "--provider", "nvidia"], 2, ["--provider mock"]),
    (["tool", "search_logs", '{"source": "wazuh", "account": "a.rao"}'], 0,
     ['"total_matched": 3', "status: OK", "wazuh_alerts.jsonl#L9"]),
    (["tool", "search_logs", '{"source": "wazuh"}'], 2, ["status: REJECTED", "at least one filter"]),
    (["tool", "lookup_ip", '{"ip": "203.0.113.77"}', "--fault", "lookup_ip:timeout", "--timeout", "0.2"], 1,
     ["status: TIMEOUT", "FAULT INJECTED"]),
    (["tool", "block_ip", '{"ip": "203.0.113.77"}'], 2, ["Unknown tool 'block_ip'"]),
    (["tool", "lookup_ip", "{not json"], 2, ["not valid JSON"]),
    (["tool", "get_alert", '{"alert_id": "ALERT-2026-0001"}'], 0, ['"data_label": "SYNTHETIC LAB DATA"']),
    (["tool", "submit_investigation_plan", "{}"], 2, ["Unknown tool"]),
    (["trace", "INV-20991231-DEADBEEF"], 1, ["No investigation record"]),
    (["trace", "../../etc/passwd"], 2, ["Invalid investigation id"]),
    (["check"], 0, ["  investigate     get_alert, get_asset_context, lookup_ip, search_cve, search_logs, "
                    "submit_evidence_log", "  data dir        data  OK", "NVIDIA_API_KEY  MISSING", "check: OK"]),
], ids=["investigate", "investigate-fake-ref", "investigate-fault", "investigate-bad-fault",
        "investigate-missing-key", "tool-ok", "tool-rejected", "tool-timeout", "tool-unknown", "tool-bad-json",
        "tool-get-alert", "tool-no-submit", "trace-missing", "trace-traversal", "check"])
def test_cli(argv, code, needles, mock_settings, capsys, monkeypatch):
    from soc_agent.cli import main
    monkeypatch.chdir(ROOT)
    assert main(argv) == code
    out = capsys.readouterr()
    for needle in needles:
        assert needle in out.out + out.err, needle


def test_cli_trace_reprints_a_stored_investigation(alert, mock_settings, capsys, monkeypatch):
    from soc_agent.cli import main
    monkeypatch.chdir(ROOT)
    _, inv, _ = investigate(alert, mock_settings)
    capsys.readouterr()
    assert main(["trace", inv.investigation_id]) == 0
    out = capsys.readouterr().out
    assert inv.investigation_id in out and "Tool-call trace (7 call(s))" in out and "Evidence log (accepted" in out
    assert main(["trace", inv.investigation_id, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["trace"] == inv.trace


# --------------------------------------------------------------------------------- API
def test_api_investigate_and_trace(wazuh_raw, mock_settings):
    from soc_agent.api import app
    client = TestClient(app)
    r = client.post("/alerts/investigate?provider=mock", json=wazuh_raw)
    assert r.status_code == 200, r.text
    body = r.json()
    inv = body["investigation"]
    assert body["plan"]["status"] == "planned" and inv["status"] == "completed"
    assert inv["investigation_id"] == body["plan"]["investigation_id"]
    t = client.get(f"/runs/{inv['investigation_id']}/trace")
    assert t.status_code == 200 and t.json()["trace"] == inv["trace"] and t.json()["phase"] == "investigation"
    assert client.get(f"/runs/{inv['investigation_id']}").json()["phase"] == "planning"
    assert client.get("/runs/INV-20991231-DEADBEEF/trace").status_code == 404
    assert client.get("/runs/INV-1/trace").status_code == 400


def test_api_investigate_errors(alert, mock_settings, monkeypatch):
    from soc_agent.api import app
    monkeypatch.setenv("SOC_TOOL_TIMEOUT_S", "0.3")          # the API loads its settings per request
    client = TestClient(app)
    clean = {k: v for k, v in alert.items() if k != "raw"}
    assert client.post("/alerts/investigate?provider=mock&scenario=escape", json=clean).status_code == 422
    assert client.post("/alerts/investigate?provider=nvidia", json=clean).status_code == 503
    assert client.post("/alerts/investigate?provider=mock", json={"foo": 1}).status_code == 422
    r = client.post("/alerts/investigate?provider=mock&scenario=investigate_tool_failure", json=clean)
    assert r.status_code == 200 and r.json()["investigation"]["faults"] == {"lookup_ip": "timeout"}


# ------------------------------------------------- investigation phase only, from a saved plan
def test_investigate_with_a_saved_plan_and_rerun_keeps_the_earlier_record(alert, mock_settings, capsys,
                                                                          monkeypatch, tmp_path):
    from soc_agent.cli import main
    monkeypatch.chdir(ROOT)
    res = plan_investigation(alert, mock_settings)
    for source in (res.run_record, tmp_path / "plan.json"):         # a planning run record, or `plan --out`
        (tmp_path / "plan.json").write_text(json.dumps(res.plan))
        assert main(["investigate", "data/alerts/account_compromise.json", "--provider", "mock",
                     "--plan", str(source)]) == 0
        assert "status: COMPLETED" in capsys.readouterr().out
    records = sorted(p.name for p in mock_settings.runs_dir.glob(f"{res.investigation_id}.investigation*.json"))
    assert len(records) == 2 and f"{res.investigation_id}.investigation.json" in records   # nothing overwritten


@pytest.mark.parametrize("mutate, needle", [
    (lambda p: p.update(alert_id="ALERT-OTHER"), "the plan is for alert ALERT-OTHER"),
    (lambda p: p["steps"][0]["parameters"].update(src_ip="198.51.100.9"), "198.51.100.9 does not appear"),
    (lambda p: p.pop("plan_id"), "holds no accepted plan"),
    (lambda p: p.clear() or p.update(x=1), "holds no accepted plan"),
])
def test_a_bad_saved_plan_is_refused(alert, mock_settings, capsys, monkeypatch, tmp_path, mutate, needle):
    from soc_agent.cli import main
    monkeypatch.chdir(ROOT)
    plan = plan_investigation(alert, mock_settings).plan
    mutate(plan)
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    assert main(["investigate", "data/alerts/account_compromise.json", "--provider", "mock",
                 "--plan", str(tmp_path / "plan.json")]) == 2
    assert needle in capsys.readouterr().err


# ------------------------------------- calls Hermes answers itself (invalid JSON arguments)
def _msgs():
    def call(i, name, args, text):
        return {"role": "assistant", "content": text,
                "tool_calls": [{"id": f"c{i}", "type": "function", "function": {"name": name, "arguments": args}}]}
    return [
        {"role": "user", "content": "task"},
        call(1, "lookup_ip", '{"ip": "203.0', "Step 3: broken"),
        {"role": "tool", "tool_call_id": "c1", "content": "Error: Invalid JSON arguments. Expecting ... Please retry"},
        call(2, "lookup_ip", '{"ip": "203.0.113.77"}', "Step 3: fixed"),
        {"role": "tool", "tool_call_id": "c2", "content": '{"ip": "203.0.113.77"}'},
        call(3, "terminal", '{"command": "id"}', "escape"),
        {"role": "tool", "tool_call_id": "c3", "content": "Tool 'terminal' does not exist"},
    ]


def test_calls_answered_by_hermes_are_recorded_and_do_not_shift_reasons():
    from soc_agent.investigator import build_trace
    from soc_agent.planner import refused_tool_calls, refused_warnings
    refused = refused_tool_calls(_msgs(), {"lookup_ip"})
    assert [(c["tool"], c["status"]) for c in refused] == [("lookup_ip", "invalid_json_rejected_by_hermes"),
                                                           ("terminal", "refused_by_hermes")]
    warnings = " ".join(refused_warnings(refused))
    assert "not valid JSON: ['lookup_ip']" in warnings and "outside the approved toolset: ['terminal']" in warnings
    audit = [{"seq": 1, "tool": "lookup_ip", "arguments": {"ip": "203.0.113.77"}, "status": "ok",
              "duration_ms": 1.0, "result_summary": "x", "evidence_refs": [], "fault_injected": None}]
    assert build_trace(audit, _msgs())[0]["reason"] == "Step 3: fixed"     # not the broken call's text


def test_a_saved_plan_that_is_a_json_list_is_refused(alert, mock_settings, capsys, monkeypatch, tmp_path):
    from soc_agent.cli import main
    monkeypatch.chdir(ROOT)
    (tmp_path / "plan.json").write_text("[1, 2]")
    assert main(["investigate", "data/alerts/account_compromise.json", "--provider", "mock",
                 "--plan", str(tmp_path / "plan.json")]) == 2
    assert "expected a JSON object" in capsys.readouterr().err


@pytest.mark.parametrize("argv, code, needle", [
    (["tool", "lookup_ip", '{"ip": "203.0.113.77"}'], 0, '"classification": "malicious"'),
    (["tool", "get_alert", '{"alert_id": "ALERT-2026-0001"}'], 0, '"alert_id": "ALERT-2026-0001"'),
    (["tool", "lookup_ip", '{"ip": "203.0.113.77"}', "--timeout", "0"], 2, "--timeout must be between"),
    (["tool", "lookup_ip", '{"ip": "203.0.113.77"}', "--timeout", "-1"], 2, "--timeout must be between"),
    (["tool", "get_alert", '{"alert_id": "x"}', "--alert", "nope.json"], 2, "Alert rejected"),
])
def test_tool_command_works_from_any_directory(argv, code, needle, mock_settings, capsys, monkeypatch, tmp_path):
    from soc_agent.cli import main
    monkeypatch.chdir(tmp_path)                              # not the project folder
    assert main(argv) == code
    out = capsys.readouterr()
    assert needle in out.out + out.err
