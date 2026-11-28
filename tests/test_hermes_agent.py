"""End to end through the real Hermes runtime (hermes-agent 0.19.0), driven by the offline mock LLM."""
import json
import os
from pathlib import Path

import pytest

from soc_agent.mock_llm import ESCAPE_MARKER, FINAL_REPLY, INVENTED_IP
from soc_agent.planner import MOCK_WARNING, plan_investigation
from soc_agent.schemas import load_schema, problems


def run(alert, settings, scenario="normal"):
    res = plan_investigation(alert, settings, mock_scenario=scenario)
    record = json.loads(Path(res.run_record).read_text())
    return res, record


def tools_and_status(record):
    return [(c["tool"], c["status"]) for c in record["tool_calls"]]


def test_normal_alert_to_plan(alert, mock_settings):
    res, rec = run(alert, mock_settings)
    assert res.status == "planned" and res.error is None
    assert res.investigation_id.startswith("INV-") and len(res.investigation_id) == 21
    p = res.plan
    assert p["plan_id"] == f"PLAN-{res.investigation_id}" and p["alert_id"] == "ALERT-2026-0001"
    assert p["generated_by"] == {"runtime": "hermes-agent", "provider": "mock",
                                 "model": "mock-soc-planner", "mock": True}
    assert p["synthetic_data"] is True and MOCK_WARNING in res.warnings
    content = {k: v for k, v in p.items() if k not in
               ("plan_id", "investigation_id", "alert_id", "created_at", "generated_by", "synthetic_data")}
    assert problems(content, load_schema("investigation_plan")) == []
    # run record
    assert rec["task"]["system_prompt"].startswith("You are a junior SOC")
    assert "alert_id=ALERT-2026-0001" in rec["task"]["user_message"]
    assert tools_and_status(rec) == [("get_alert", "ok"), ("submit_investigation_plan", "ok")]
    assert rec["hermes"]["completed"] is True and rec["hermes"]["final_response"] == FINAL_REPLY
    assert rec["status"] == "planned" and rec["plan"] == p and rec["refused_tool_calls"] == []
    assert "raw" not in rec["alert"]


def test_hermes_home_is_project_local_not_user_home(alert, mock_settings, tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    run(alert, mock_settings)
    assert list(home.iterdir()) == []                  # ~/.hermes is never created or touched
    assert os.environ["HERMES_HOME"] == str(mock_settings.hermes_home)
    assert mock_settings.hermes_home.is_dir()
    assert "127.0.0.1" in os.environ["NO_PROXY"]


def test_only_soc_tools_are_exposed(alert, mock_settings):
    _, rec = run(alert, mock_settings)
    assert rec["exposed_tools"] == ["get_alert", "submit_investigation_plan"]


def test_escape_to_builtin_terminal_is_refused(alert, mock_settings):
    ESCAPE_MARKER.unlink(missing_ok=True)
    res, rec = run(alert, mock_settings, "escape")
    assert not ESCAPE_MARKER.exists()                            # the command never ran
    refused = rec["refused_tool_calls"]
    assert len(refused) == 1 and refused[0]["tool"] == "terminal"
    assert refused[0]["status"] == "refused_by_hermes" and "does not exist" in refused[0]["hermes_reply"]
    assert "terminal" not in [c["tool"] for c in rec["tool_calls"]]   # never reached our tool layer
    assert any("Hermes refused 1 call" in w for w in res.warnings)
    assert res.status == "planned"                               # the agent recovered safely


def test_invalid_plan_is_rejected_then_fixed(alert, mock_settings):
    res, rec = run(alert, mock_settings, "invalid_first")
    assert tools_and_status(rec) == [("get_alert", "ok"), ("submit_investigation_plan", "rejected"),
                                     ("submit_investigation_plan", "ok")]
    assert INVENTED_IP in " ".join(rec["tool_calls"][1]["result"]["problems"])
    assert res.status == "planned" and INVENTED_IP not in json.dumps(res.plan)


def test_malformed_tool_arguments_are_rejected_then_recovered(alert, mock_settings):
    res, rec = run(alert, mock_settings, "bad_args")
    first = rec["tool_calls"][0]
    assert first["status"] == "rejected" and first["arguments"] == {"alert": "ALERT-2026-0001", "extra": 1}
    assert first["result"]["error"] == "Invalid arguments for get_alert."
    assert tools_and_status(rec)[1:] == [("get_alert", "ok"), ("submit_investigation_plan", "ok")]
    assert res.status == "planned"


def test_malformed_json_string_plan_is_explained_then_fixed(alert, mock_settings):
    res, rec = run(alert, mock_settings, "string_plan")         # what a live NVIDIA model did
    assert tools_and_status(rec) == [("get_alert", "ok"), ("submit_investigation_plan", "rejected"),
                                     ("submit_investigation_plan", "ok")]
    assert "not valid JSON" in rec["tool_calls"][1]["result"]["problems"][0]
    assert res.status == "planned"


def test_no_submitted_plan_means_failed_not_invented(alert, mock_settings):
    res, rec = run(alert, mock_settings, "no_submit")
    assert res.status == "failed" and res.plan is None and "did not produce a valid plan" in res.error
    assert rec["status"] == "failed" and rec["plan"] is None and rec["tool_calls"] == []


def test_llm_outage_fails_safely(alert, mock_settings):
    res, rec = run(alert, mock_settings, "http_error")
    assert res.status == "failed" and res.plan is None and res.error
    assert rec["status"] == "failed" and rec["hermes"]["completed"] is False


def test_unknown_mock_scenario_is_refused(alert, mock_settings):
    res = plan_investigation(alert, mock_settings, mock_scenario="nope")
    assert res.status == "failed" and "Unknown mock scenario" in res.error


def test_wazuh_input_end_to_end(wazuh_raw, mock_settings):
    from soc_agent.alerts import normalize
    res, rec = run(normalize(wazuh_raw), mock_settings)
    assert res.status == "planned" and res.alert_id == "WAZUH-1763458937.4471"


@pytest.mark.parametrize("argv, code, needle", [
    (["plan", "data/alerts/account_compromise.json", "--provider", "mock"], 0, "MOCK SCRIPT - NOT AN AI MODEL"),
    (["plan", "data/alerts/account_compromise.json", "--provider", "mock", "--scenario", "no_submit"], 1, "No plan"),
    (["plan", "data/alerts/invalid/bad_alert.json", "--provider", "mock"], 2, "Alert rejected"),
    (["plan", "data/alerts/account_compromise.json", "--provider", "nvidia"], 2, "--provider mock"),
    (["validate-alert", "data/alerts/wazuh_account_compromise.json"], 0, '"account": "j.mehta"'),
    (["check"], 0, "  plan            get_alert, submit_investigation_plan"),
], ids=["plan-mock", "plan-no-submit", "plan-invalid-alert", "plan-missing-key", "validate-wazuh", "check"])
def test_cli(argv, code, needle, mock_settings, capsys, monkeypatch):
    from soc_agent.cli import main
    monkeypatch.chdir(Path(__file__).resolve().parent.parent)
    assert main(argv) == code
    out = capsys.readouterr()
    assert needle in out.out + out.err


def test_cli_json_and_out(tmp_path, mock_settings, capsys, monkeypatch):
    from soc_agent.cli import main
    monkeypatch.chdir(Path(__file__).resolve().parent.parent)
    out_file = tmp_path / "plan.json"
    assert main(["plan", "data/alerts/account_compromise.json", "--provider", "mock", "--json",
                 "--out", str(out_file)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "planned" and json.loads(out_file.read_text()) == result["plan"]
