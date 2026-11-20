"""Plan schema, 'no invented indicators' check, tool wrapper (validation, permissions, audit)."""
import json

import pytest

from soc_agent.mock_llm import build_mock_plan
from soc_agent.schemas import load_schema, problems
from soc_agent.tools.base import RunContext, ToolSpec, close_run, open_run, wrap
from soc_agent.tools.planning import (GET_ALERT, MAX_PLAN_ATTEMPTS, SUBMIT_PLAN, plan_problems,
                                      plan_quality_notes, unsupported_values)

PLAN_SCHEMA = load_schema("investigation_plan")


# ----------------------------------------------------------------- plan schema
def test_mock_plan_matches_schema(alert):
    plan = build_mock_plan(alert)
    assert problems(plan, PLAN_SCHEMA) == [] and plan_problems(plan, alert) == []
    assert any(h["benign"] for h in plan["hypotheses"])
    assert {s["tool"] for s in plan["steps"]} == {"search_logs", "lookup_ip", "get_asset_context",
                                                  "search_cve", "analyst_review"}
    assert plan["summary"].startswith("[MOCK]")


@pytest.mark.parametrize("mutate, expected", [
    (lambda p: p.pop("hypotheses"), "hypotheses"),
    (lambda p: p.pop("safety_notes"), "safety_notes"),
    (lambda p: p.update(verdict="malicious"), "verdict"),
    (lambda p: p["steps"][0].update(tool="block_ip"), "block_ip"),
    (lambda p: p["steps"][0].update(command="rm -rf /"), "command"),
    (lambda p: p["hypotheses"][0].pop("benign"), "benign"),
    (lambda p: [h.update(benign=False) for h in p["hypotheses"]], "contain"),
    (lambda p: p.update(hypotheses=p["hypotheses"][:1]), "short"),
    (lambda p: p.update(steps=p["steps"][:2]), "short"),
    (lambda p: p.update(key_questions=["a?"] * 11), "long"),
])
def test_plan_schema_rejects_missing_unknown_and_bad_fields(alert, mutate, expected):
    plan = build_mock_plan(alert)
    mutate(plan)
    assert expected in " ".join(problems(plan, PLAN_SCHEMA))


def test_step_order_and_unique_hypothesis_ids(alert):
    plan = build_mock_plan(alert)
    plan["steps"][0]["step"] = 2
    plan["hypotheses"][1]["id"] = "H1"
    issues = " ".join(plan_problems(plan, alert))
    assert "numbered" in issues and "unique" in issues


def test_plan_may_not_invent_indicators(alert):
    plan = build_mock_plan(alert)
    plan["steps"][1]["parameters"] = {"src_ip": "198.51.100.9"}                 # not in the alert
    plan["steps"][0]["parameters"]["account"] = "admin"                          # not in the alert
    plan["steps"][3]["parameters"] = {"host": "dc-01"}                           # not in the alert
    plan["steps"][4]["parameters"] = {"filters": [{"query": "from 192.0.2.5"}]}  # nested, not in the alert
    issues = " ".join(unsupported_values(plan, alert))
    for bad in ("198.51.100.9", "admin", "dc-01", "192.0.2.5"):
        assert bad in issues


def test_alert_indicators_are_accepted_case_insensitively(alert):
    plan = build_mock_plan(alert)
    plan["steps"][0]["parameters"] = {"account": "J.Mehta", "host": "FIN-APP-01", "dst_ip": "10.20.5.17"}
    assert unsupported_values(plan, alert) == []


def test_host_may_be_named_by_alert_ip_and_versions_are_not_ips(alert):
    plan = build_mock_plan(alert)
    plan["steps"][3]["parameters"] = {"host": "10.20.5.17"}                     # dst_ip of the alert
    plan["steps"][5]["parameters"] = {"product": "openssh", "version": "8.9.1.2"}
    assert unsupported_values(plan, alert) == []
    plan["steps"][3]["parameters"] = {"host": "10.20.5.99"}                     # still invented
    assert "10.20.5.99" in " ".join(unsupported_values(plan, alert))


# ------------------------------------------------------------------ wrapper
def _call(spec, args, ctx):
    open_run(ctx)
    try:
        return json.loads(wrap(spec)(args, task_id=ctx.investigation_id, session_id="s"))
    finally:
        close_run(ctx.investigation_id)


def test_wrapper_validates_arguments_before_the_handler_and_audits(alert):
    calls = []
    spec = ToolSpec("echo", "echo", {"type": "object", "properties": {"x": {"type": "integer"}},
                                     "required": ["x"], "additionalProperties": False},
                    handler=lambda a, c: calls.append(a) or {"x": a["x"]})
    ctx = RunContext("INV-TEST-1", alert)
    out = _call(spec, {"x": "1", "y": 2}, ctx)
    assert out["error"].startswith("Invalid arguments") and calls == []       # handler never ran
    assert any("'1' is not of type 'integer'" in p for p in out["problems"])
    assert any("'y' was unexpected" in p for p in out["problems"])
    assert _call(spec, {"x": 1}, ctx) == {"x": 1}
    assert [c["status"] for c in ctx.tool_calls] == ["rejected", "ok"]
    entry = ctx.tool_calls[1]
    assert set(entry) == {"seq", "tool", "permission", "arguments", "status", "result",
                          "started_at", "finished_at", "duration_ms"}
    assert entry["seq"] == 2 and entry["permission"] == "read" and entry["duration_ms"] >= 0


def test_wrapper_rejects_non_object_arguments(alert):
    ctx = RunContext("INV-TEST-6", alert)
    assert "JSON object" in _call(GET_ALERT, "ALERT-2026-0001", ctx)["error"]
    assert ctx.tool_calls[0]["status"] == "rejected"


def test_unknown_task_id_is_refused(alert):
    out = json.loads(wrap(GET_ALERT)({"alert_id": alert["alert_id"]}, task_id="INV-NOT-OPEN"))
    assert "No active investigation" in out["error"]


def test_get_alert_minimizes_data_and_refuses_other_alerts(alert, wazuh_raw):
    from soc_agent.alerts import normalize
    w = normalize(wazuh_raw)
    ctx = RunContext("INV-TEST-2", w)
    out = _call(GET_ALERT, {"alert_id": w["alert_id"]}, ctx)
    assert "raw" not in out["alert"] and "full_log" not in json.dumps(out)
    assert out["data_label"] == "SYNTHETIC LAB DATA"
    out = _call(GET_ALERT, {"alert_id": "ALERT-9999"}, ctx)
    assert "Unknown alert_id" in out["error"] and ctx.tool_calls[-1]["status"] == "rejected"


def test_disruptive_tool_is_denied(alert):
    calls = []
    block = ToolSpec("block_ip", "Block an IP (simulated)", {"type": "object", "properties": {
        "ip": {"type": "string"}}, "required": ["ip"], "additionalProperties": False},
        handler=lambda a, c: calls.append(a) or {"blocked": True}, permission="disruptive")
    ctx = RunContext("INV-TEST-3", alert)                # runs allow read + write_internal only
    out = _call(block, {"ip": "203.0.113.77"}, ctx)
    assert "needs permission 'disruptive'" in out["error"] and calls == []
    assert ctx.tool_calls[0]["status"] == "denied" and ctx.tool_calls[0]["permission"] == "disruptive"


def test_unknown_permission_is_refused():
    with pytest.raises(ValueError, match="unknown permission"):
        ToolSpec("x", "x", {"type": "object"}, handler=lambda a, c: {}, permission="admin")


def test_tool_exceptions_become_errors(alert):
    boom = ToolSpec("boom", "fails", {"type": "object", "properties": {}, "additionalProperties": False},
                    handler=lambda a, c: 1 / 0)
    ctx = RunContext("INV-TEST-4", alert)
    out = _call(boom, {}, ctx)
    assert "ZeroDivisionError" in out["error"] and ctx.tool_calls[0]["status"] == "error"


def test_invented_indicator_is_rejected_by_the_submit_tool(alert):
    ctx = RunContext("INV-TEST-7", alert)
    plan = build_mock_plan(alert)
    plan["steps"][2]["parameters"] = {"ip": "198.51.100.23"}
    out = _call(SUBMIT_PLAN, {"plan": plan}, ctx)
    assert out["error"] == "Plan rejected." and "198.51.100.23" in " ".join(out["problems"])
    assert ctx.plan is None and ctx.tool_calls[0]["status"] == "rejected"


def test_only_one_accepted_plan(alert):
    ctx = RunContext("INV-TEST-5", alert)
    good = build_mock_plan(alert)
    assert _call(SUBMIT_PLAN, {"plan": good}, ctx)["accepted"] is True
    assert "already accepted" in _call(SUBMIT_PLAN, {"plan": good}, ctx)["error"]
    assert ctx.plan == good and [c["status"] for c in ctx.tool_calls] == ["ok", "rejected"]


def test_plan_attempts_are_limited(alert):
    ctx = RunContext("INV-TEST-8", alert)
    bad = build_mock_plan(alert)
    bad.pop("hypotheses")                                 # schema error: rejected by the wrapper
    for _ in range(MAX_PLAN_ATTEMPTS):
        assert "error" in _call(SUBMIT_PLAN, {"plan": bad}, ctx)
    out = _call(SUBMIT_PLAN, {"plan": build_mock_plan(alert)}, ctx)   # valid, but too late
    assert "Too many plan submissions" in out["error"] and ctx.plan is None


def test_full_schema_still_applies_behind_the_simplified_model_schema(alert):
    assert "contains" not in json.dumps(SUBMIT_PLAN.parameters)      # what the model is sent
    ctx = RunContext("INV-TEST-9", alert)
    plan = build_mock_plan(alert)
    for h in plan["hypotheses"]:
        h["benign"] = False                                           # no benign hypothesis
    out = _call(SUBMIT_PLAN, {"plan": plan}, ctx)
    assert out["error"] == "Plan rejected." and ctx.plan is None
    assert any("hypotheses" in p for p in out["problems"])


def test_concurrent_submissions_accept_exactly_one_plan(alert):
    from concurrent.futures import ThreadPoolExecutor
    ctx = RunContext("INV-TEST-10", alert)
    open_run(ctx)
    try:
        h = wrap(SUBMIT_PLAN)
        with ThreadPoolExecutor(8) as ex:
            outs = [json.loads(o) for o in ex.map(
                lambda _: h({"plan": build_mock_plan(alert)}, task_id=ctx.investigation_id), range(8))]
    finally:
        close_run(ctx.investigation_id)
    assert sum(o.get("accepted") is True for o in outs) == 1
    assert [c["seq"] for c in ctx.tool_calls] == list(range(1, 9))


def test_plan_sent_as_malformed_json_string_gets_a_precise_short_problem(alert):
    ctx = RunContext("INV-TEST-11", alert)
    broken = json.dumps(build_mock_plan(alert)).replace('}, "rationale"', '}}, "rationale"', 1)
    out = _call(SUBMIT_PLAN, {"plan": broken}, ctx)
    assert out["error"].startswith("Invalid arguments") and ctx.plan is None
    first = out["problems"][0]
    assert first.startswith("plan: must be a JSON object, not a string") and "Expecting ',' delimiter" in first
    assert len(out["problems"]) == 1                           # no duplicate generic type error
    assert len(json.dumps(out)) < 1500 < len(broken)           # the plan is not echoed back in full


def test_plan_sent_as_valid_json_string_is_explained(alert):
    ctx = RunContext("INV-TEST-12", alert)                    # Hermes decodes these; direct callers get told
    out = _call(SUBMIT_PLAN, {"plan": json.dumps(build_mock_plan(alert))}, ctx)
    assert out["problems"][0] == "plan: must be a JSON object, not a string containing JSON."


def test_quality_notes_flag_duplicate_review_and_repeated_steps(alert):
    plan = build_mock_plan(alert)
    assert plan_quality_notes(plan) == []
    plan["steps"].append(dict(plan["steps"][-1], step=8))                    # second analyst_review
    plan["steps"].append(dict(plan["steps"][2], step=9))                     # same lookup_ip again
    notes = " ".join(plan_quality_notes(plan))
    assert "2 analyst_review steps" in notes and "Step 9 repeats step 3" in notes
