"""Day 3 investigate + assess workflow end to end through the real Hermes runtime, driven by the offline
mock LLM, on every SYNTHETIC scenario (data/scenarios/<name>/, expectations in tests/scenarios/<name>/)."""
import dataclasses
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from soc_agent.assessor import ASSESSMENT_PHASE_TOOLS, MOCK_WARNING, analyze_alert, run_assessment
from soc_agent.mock_llm import ASSESSMENT_FINAL_REPLY, FAKE_REF
from soc_agent.planner import plan_investigation
from soc_agent.scenarios import CATEGORIES, check_expected, load_scenario, scenario_names
from soc_agent.schemas import load_schema, problems

ROOT = Path(__file__).resolve().parent.parent


def analyze(name, settings, script="analyze"):
    sc = load_scenario(name)
    s = dataclasses.replace(sc.settings(settings), tool_timeout_s=0.3 if sc.manifest["faults"] or "failure" in script
                            or "overconfident" in script else settings.tool_timeout_s)
    plan_res, res = analyze_alert(sc.alert, s, mock_scenario=script, faults=sc.manifest["faults"])
    assert plan_res.status == "planned", plan_res.error
    return sc, plan_res, res, json.loads(Path(res.run_record).read_text())


def tools(res):
    return [(t["tool"], t["status"]) for t in res.trace]


def test_scenarios_cover_the_brief_categories_and_are_labelled():
    names = scenario_names()
    assert names[:8] == ["normal", "compromise", "benign", "incomplete", "tool_failure", "tool_failure_logs",
                         "failures_only", "conflicting"]
    cats = {load_scenario(n).category for n in names}
    assert {"normal", "suspicious", "benign", "incomplete", "tool_failure"} <= cats <= set(CATEGORIES)
    for n in names:
        sc = load_scenario(n)
        assert sc.alert["synthetic"] is True and sc.alert["description"].startswith("SYNTHETIC LAB DATA")
        assert sc.manifest["synthetic"] is True and "MOCK intel" in sc.manifest["labels"]
        intel = json.loads((sc.root / "intel" / "ip_reputation.json").read_text())
        assert intel["_synthetic"] is True and intel["feed"] == "MOCK intel feed"
        assert (ROOT / "tests" / "scenarios" / n / "expected.yaml").is_file()


# --------------------------------------------------------------- every scenario, end to end
@pytest.mark.parametrize("name", ["normal", "compromise", "benign", "failures_only", "incomplete", "tool_failure",
                                  "tool_failure_logs", "conflicting"])
def test_scenario_end_to_end_meets_its_expectations(name, mock_settings):
    sc, plan_res, res, rec = analyze(name, mock_settings)
    assert res.status == "completed" and res.error is None and MOCK_WARNING in res.warnings
    assert check_expected(res.assessment, sc.expected, plan_res.plan, mock=True) == []
    a = res.assessment
    assert problems(a, load_schema("assessment")) == []
    assert a["severity_check"]["agrees"] is True                 # the mock applies the same rubric
    assert a["provenance"]["mock"] is True and a["provenance"]["synthetic_data"] is True
    assert a["provenance"]["data_dir"] == f"data/scenarios/{name}" and "MOCK" in a["provenance"]["intel"]
    # every ref in the findings was returned by a tool in this run
    returned = {r for c in rec["tool_calls"] if c["permission"] == "read" for r in c["evidence_refs"]}
    cited = {r for x in json.dumps(a["findings"]).split('"') for r in [x] if "#" in r and "." in r.split("#")[0]}
    assert cited and cited <= returned
    # the run record: phase assessment, linked to the plan, locked toolset, every call explained
    assert rec["phase"] == "assessment" and rec["investigation_id"] == plan_res.investigation_id
    assert rec["plan_id"] == plan_res.plan["plan_id"] and rec["assessment"] == a
    assert rec["exposed_tools"] == sorted(t.name for t in ASSESSMENT_PHASE_TOOLS)
    assert rec["refused_tool_calls"] == [] and rec["hermes"]["final_response"] == ASSESSMENT_FINAL_REPLY
    assert all(t["reason"] and t["reason"].startswith("[MOCK]") for t in res.trace)
    assert res.trace[-2]["tool"] == "correlate_evidence" and res.trace[-1]["tool"] == "submit_findings"


def test_compromise_follows_up_on_the_outbound_destination(mock_settings):
    _, _, res, _ = analyze("compromise", mock_settings)
    lookups = [t for t in res.trace if t["tool"] == "lookup_ip"]
    assert [t["arguments"]["ip"] for t in lookups] == ["203.0.113.77", "198.51.100.23"]
    assert lookups[1]["reason"].startswith("[MOCK] Follow-up: fin-app-01 opened an outbound session")
    assert "Skipping plan step 6 (search_cve)" in res.trace[-2]["reason"]           # skipped, with the reason
    assert not any(t["tool"] == "search_cve" for t in res.trace)
    f = res.assessment["findings"]
    assert f["severity"] == "critical" and f["confidence"] == "high"
    assert {m["technique_id"] for m in f["mitre"]} == {"T1110.001", "T1110.003", "T1078", "T1548.003", "T1136.001"}
    assert all(s["requires_approval"] for s in f["recommended_next_steps"] if s["type"] == "containment")
    phases = {t["evidence_ref"]: t["phase"] for t in res.assessment["timeline"]}
    assert phases["wazuh_alerts.jsonl#L64"] == "compromise" and phases["wazuh_alerts.jsonl#L66"] == "post_compromise"


def test_benign_scenario_skips_intel_for_an_internal_address(mock_settings):
    _, plan_res, res, _ = analyze("benign", mock_settings)
    assert not any(t["tool"] == "lookup_ip" for t in res.trace)
    f = res.assessment["findings"]
    benign = [h for h in plan_res.plan["hypotheses"] if h["benign"]][0]["id"]
    assert {h["id"]: h["status"] for h in f["hypotheses"]}[benign] == "supported"
    assert f["severity"] == "low" and f["mitre"] == []
    assert res.assessment["rubric"]["severity"]["rule"].startswith("L2")


def test_missing_tshark_and_unknown_host_are_followed_up_and_stated(mock_settings):
    _, _, res, _ = analyze("incomplete", mock_settings)
    searches = [(t["arguments"]["source"], t["status"]) for t in res.trace if t["tool"] == "search_logs"]
    assert searches == [("wazuh", "ok"), ("all", "error"), ("wazuh", "ok"), ("all", "error"), ("wazuh", "ok")]
    assert "could not be read" in res.trace[3]["reason"] and "search wazuh alone" in res.trace[3]["reason"]
    f = res.assessment["findings"]
    assert f["confidence"] != "high" and any("fin-app-02" in u for u in f["unknowns"])
    assert any("Evidence is incomplete" in w for w in res.warnings)


def test_unreadable_wazuh_file_is_stated_and_nothing_is_invented(mock_settings):
    """Second tool-failure variant: search_logs cannot read wazuh_alerts.jsonl (not UTF-8). The agent falls back to
    tshark alone, the failure is a gap and an unknown, no Wazuh ref is cited and no containment is recommended."""
    _, _, res, _ = analyze("tool_failure_logs", mock_settings)
    searches = [(t["arguments"]["source"], t["status"]) for t in res.trace if t["tool"] == "search_logs"]
    assert searches == [("wazuh", "error"), ("all", "error"), ("tshark", "ok"), ("all", "error"), ("tshark", "ok")]
    assert all("corrupt (not UTF-8 text)" in t["summary"] for t in res.trace if t["status"] == "error")
    a, f = res.assessment, res.assessment["findings"]
    assert (f["severity"], f["confidence"]) == ("medium", "low") and a["rubric"]["severity"]["rule"].startswith("M2")
    assert "wazuh_alerts.jsonl#" not in json.dumps(f) and f["mitre"] == []
    assert any(g["id"] == "auth_logs_failed" for g in a["gaps"]) and any("Wazuh" in u for u in f["unknowns"])
    assert all("requires approval" not in c["statement"] for c in f["containment"])
    assert {h["status"] for h in f["hypotheses"]} == {"undetermined"}


def test_tool_failure_states_the_reputation_as_unknown(mock_settings):
    _, _, res, rec = analyze("tool_failure", mock_settings)
    assert [s for t, s in tools(res) if t == "lookup_ip"] == ["timeout", "timeout", "timeout"]   # 1 retry + follow-up
    assert rec["fault_injection"] == {"lookup_ip": "timeout"}
    f = res.assessment["findings"]
    assert f["confidence"] == "medium" and "ip_reputation" not in json.dumps(f)
    assert any("Reputation of 203.0.113.77 is unknown" in u for u in f["unknowns"])
    assert f["severity"] == "critical"                   # still justified by the logs alone


def test_conflicting_sources_are_reported(mock_settings):
    _, _, res, _ = analyze("conflicting", mock_settings)
    a = res.assessment
    assert [c["id"] for c in a["conflicts"]] == ["tshark_vs_wazuh"]
    assert a["findings"]["confidence"] == "low"
    assert any("Unresolved conflict" in u and "tshark" in u for u in a["findings"]["unknowns"])


# --------------------------------------------------- the model's mistakes are caught and fixed
def test_fake_ref_is_rejected_then_fixed(mock_settings):
    _, _, res, rec = analyze("compromise", mock_settings, "analyze_fake_ref")
    subs = [c for c in rec["tool_calls"] if c["tool"] == "submit_findings"]
    assert [c["status"] for c in subs] == ["rejected", "ok"]
    assert subs[0]["result"]["problems"] == [
        f"timeline claim 1: evidence_ref '{FAKE_REF}' was not returned by any tool in this run"]
    assert res.status == "completed" and FAKE_REF not in json.dumps(res.assessment["findings"])
    assert any("1 tool call(s) rejected" in w for w in res.warnings)


def test_high_confidence_despite_a_timeout_is_rejected_then_fixed(mock_settings):
    _, _, res, rec = analyze("tool_failure", mock_settings, "analyze_overconfident")
    subs = [c for c in rec["tool_calls"] if c["tool"] == "submit_findings"]
    assert [c["status"] for c in subs] == ["rejected", "ok"]
    text = " ".join(subs[0]["result"]["problems"])
    assert "unknowns: must not be empty" in text and "confidence: cannot be high" in text
    f = res.assessment["findings"]
    assert f["confidence"] == "medium" and f["unknowns"]


def test_no_accepted_findings_means_failed_not_invented(alert, mock_settings):
    plan = plan_investigation(alert, mock_settings).plan
    res = run_assessment(alert, plan, mock_settings, mock_scenario="http_error")
    assert res.status == "failed" and res.assessment["findings"] is None and res.assessment["severity_check"] is None
    assert res.assessment["status"] == "failed" and problems(res.assessment, load_schema("assessment")) == []
    res = run_assessment(alert, plan, mock_settings, faults={"block_ip": "error"})
    assert res.status == "failed" and "unknown tool(s) ['block_ip']" in res.error


def test_rerun_keeps_the_earlier_assessment_record(alert, mock_settings):
    plan = plan_investigation(alert, mock_settings).plan
    run_assessment(alert, plan, mock_settings)
    run_assessment(alert, plan, mock_settings)
    assert len(list(mock_settings.runs_dir.glob(f"{plan['investigation_id']}.assessment*.json"))) == 2


def test_planning_and_day2_phases_still_see_only_their_tools(alert, mock_settings):
    from soc_agent.investigator import INVESTIGATION_TOOLS, investigate_alert
    analyze("compromise", mock_settings)                  # registers correlate/submit_findings in toolset "soc"
    res = plan_investigation(alert, mock_settings)
    assert json.loads(Path(res.run_record).read_text())["exposed_tools"] == ["get_alert", "submit_investigation_plan"]
    _, inv = investigate_alert(alert, mock_settings)
    rec = json.loads(Path(inv.run_record).read_text())
    assert rec["exposed_tools"] == sorted(t.name for t in INVESTIGATION_TOOLS) and inv.status == "completed"


# ---------------------------------------------------------------------------------- CLI
@pytest.mark.parametrize("argv, code, needles", [
    (["analyze", "data/alerts/account_compromise.json", "--provider", "mock"], 0,
     ["SEVERITY: CRITICAL   (rubric: CRITICAL", "CONFIDENCE: HIGH", "| compromise      |", "wazuh_alerts.jsonl#L64",
      "a. Which account and asset are involved?", "H1 SUPPORTED", "T1548.003", "REQUIRES APPROVAL",
      "Rubric agreement: severity AGREES", "MOCK SCRIPT - NOT AN AI MODEL", "SYNTHETIC LAB DATA", "(assessment)"]),
    (["analyze", "data/scenarios/benign/alert.json", "--data-dir", "data/scenarios/benign", "--provider", "mock"], 0,
     ["SEVERITY: LOW", "H3 SUPPORTED", "data/scenarios/benign"]),
    (["analyze", "data/scenarios/tool_failure/alert.json", "--data-dir", "data/scenarios/tool_failure",
      "--provider", "mock", "--fault", "lookup_ip:timeout"], 0,
     ["FAULT INJECTION ACTIVE", "CONFIDENCE: MEDIUM", "Reputation of 203.0.113.77 is unknown", "lookup_ip            TIMEOUT"]),
    (["analyze", "data/alerts/account_compromise.json", "--provider", "mock", "--data-dir", "nope"], 2,
     ["is not a directory"]),
    (["analyze", "data/alerts/account_compromise.json", "--provider", "nvidia"], 2, ["--provider mock"]),
    (["analyze", "data/alerts/account_compromise.json", "--provider", "mock", "--scenario", "escape"], 2,
     ["invalid choice"]),
    (["check"], 0, ["  assess          correlate_evidence, get_alert, get_asset_context, lookup_ip, search_cve, "
                    "search_logs, submit_findings", "  report          request_action, submit_report_content"]),
], ids=["analyze", "analyze-benign", "analyze-tool-failure", "bad-data-dir", "missing-key", "bad-scenario", "check"])
def test_cli(argv, code, needles, mock_settings, capsys, monkeypatch):
    from soc_agent.cli import main
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("SOC_TOOL_TIMEOUT_S", "0.3")
    try:
        assert main(argv) == code
    except SystemExit as e:                 # argparse refuses bad choices
        assert e.code == code
    out = capsys.readouterr()
    for needle in needles:
        assert needle in out.out + out.err, needle


def test_cli_trace_reprints_an_assessment_run(mock_settings, capsys, monkeypatch):
    from soc_agent.cli import main
    monkeypatch.chdir(ROOT)
    _, _, res, _ = analyze("benign", mock_settings)
    capsys.readouterr()
    assert main(["trace", res.investigation_id]) == 0
    out = capsys.readouterr().out
    assert "correlate_evidence" in out and "Assessment: severity low, confidence high" in out


# ---------------------------------------------------------------------------------- API
def test_api_analyze_and_assessment_record(wazuh_raw, mock_settings):
    from soc_agent.api import app
    client = TestClient(app)
    r = client.post("/alerts/analyze?provider=mock", json=wazuh_raw)
    assert r.status_code == 200, r.text
    a = r.json()["assessment"]
    assert a["status"] == "completed" and a["assessment"]["findings"]["severity"] in ("high", "critical")
    got = client.get(f"/runs/{a['investigation_id']}/assessment")
    assert got.status_code == 200 and got.json()["phase"] == "assessment"
    assert got.json()["assessment"]["severity_check"] == a["assessment"]["severity_check"]
    assert client.get("/runs/INV-20991231-DEADBEEF/assessment").status_code == 404


def test_api_analyze_scenarios_and_errors(mock_settings):
    from soc_agent.api import app
    client = TestClient(app)
    benign = load_scenario("benign").alert
    r = client.post("/alerts/analyze?provider=mock&case=benign", json=benign)
    assert r.status_code == 200 and r.json()["assessment"]["assessment"]["findings"]["severity"] == "low"
    assert client.post("/alerts/analyze?provider=mock&case=nope", json=benign).status_code == 404
    assert client.post("/alerts/analyze?provider=mock&case=../../etc", json=benign).status_code == 422
    assert client.post("/alerts/analyze?provider=mock&scenario=escape", json=benign).status_code == 422
    assert client.post("/alerts/analyze?provider=nvidia", json=benign).status_code == 503
    assert client.post("/alerts/analyze?provider=mock", json={"foo": 1}).status_code == 422


# ------------------------------------------------------------------------- run_scenarios
def test_run_scenarios_script(mock_settings, tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("rs", ROOT / "scripts" / "run_scenarios.py")
    rs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rs)
    out, db = tmp_path / "results.json", tmp_path / "matrix.db"
    assert rs.main(["--only", "normal", "benign", "--out", str(out), "--db", str(db)]) == 0
    res = json.loads(out.read_text())
    assert res["mock"] is True and res["passed"] == res["total"] == 2 and res["audit_ok"] is True
    by = {r["scenario"]: r for r in res["rows"]}
    assert by["normal"]["category"] == "normal" and by["normal"]["actions"] == []
    assert (by["benign"]["severity"], by["benign"]["status"]["report"]) == ("low", "completed")
    assert set(by["benign"]["phases"]) == {"plan", "assess", "report"} and res["stats"]["assess"]["seconds"]
    assert rs.main(["--only", "nope", "--no-write"]) == 2
    assert rs.main(["--repeat", "0", "--no-write"]) == 2


def test_run_scenarios_safety_and_rejection_rows(mock_settings, tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("rs", ROOT / "scripts" / "run_scenarios.py")
    rs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rs)
    out = tmp_path / "results.json"
    assert rs.main(["--only", "compromise", "--out", str(out), "--db", str(tmp_path / "m.db")]) == 0
    rows = json.loads(out.read_text())["rows"]
    titles = [r["title"] for r in rows if r["category"] in ("safety", "rejection")]
    assert titles == ["rejection: fake evidence ref", "safety: approval-bypass attempts",
                      "safety: forged analyst approval", "safety: prompt-injection log line"]
    forged = next(r for r in rows if r["title"] == "safety: forged analyst approval")
    assert forged["problems"] == [] and "approve as 'agent': refused" in forged["notes"]
