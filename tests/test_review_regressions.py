"""Regression tests for the Day 3 bugs found in review: each test reproduces one concrete failure scenario."""
import copy
import dataclasses
import json
import threading
import time
from pathlib import Path

import pytest

from soc_agent.alerts import load_alert, normalize
from soc_agent.correlate import correlate
from soc_agent.mock_llm import build_mock_findings, build_mock_plan
from soc_agent.severity import assess_confidence, assess_severity, rubric
from soc_agent.tools.assessment import SUBMIT_FINDINGS
from soc_agent.tools.base import RunContext, call_tool
from soc_agent.tools.evidence import GET_ASSET_CONTEXT, LOOKUP_IP, SEARCH_LOGS
from soc_agent.tools.planning import GET_ALERT

ROOT = Path(__file__).resolve().parent.parent
ATTACKER, OFFICE, OUTBOUND = "203.0.113.77", "10.20.1.45", "198.51.100.23"
SUCCESS = "wazuh_alerts.jsonl#L64"


def ev(t, et, acct, src, ref, host="fin-app-01", dst="10.20.5.17"):
    return {"time": t, "source": "wazuh", "event_type": et, "account": acct, "host": host, "src_ip": src,
            "dst_ip": dst, "dst_port": None, "summary": "x", "evidence_ref": f"wazuh_alerts.jsonl#L{ref}"}


def search(args, events, truncated=False):
    return {"seq": 1, "tool": "search_logs", "arguments": args, "result": {
        "query": args, "events": events, "total_matched": len(events), "returned": len(events), "truncated": truncated,
        "malformed_lines_skipped": 0, "counts": {"by_event_type": {}, "by_source": {}}, "first_time": None,
        "last_time": None, "notes": [], "data_label": "SYNTHETIC"}}


def attack(n=50):
    out = [ev(f"2026-11-18T09:{31 + i // 6:02d}:{(i * 10) % 60:02d}.000Z", "auth_failure", "j.mehta", ATTACKER, 12 + i)
           for i in range(n)]
    return out + [ev("2026-11-18T09:42:17.512Z", "auth_success", "j.mehta", ATTACKER, 64)]


ACCOUNT_SEARCH = {"source": "wazuh", "account": "j.mehta", "start": "2026-11-11T00:00:00Z", "end": "2026-11-18T12:00:00Z"}


def facts(c):
    return {f["id"]: f for f in c["facts"]}


# ------------------------------------------------------------------------ correlation
def test_alert_without_an_account_is_unknown_not_low():
    raw = json.loads((ROOT / "data" / "alerts" / "wazuh_account_compromise.json").read_text())
    raw["data"] = {k: v for k, v in raw["data"].items() if k in ("srcip", "dstport")}
    alert = normalize(raw)
    assert "account" not in alert["entities"]
    c = correlate(alert, [search({"source": "all", "src_ip": ATTACKER}, attack())], [])
    assert c["signals"]["success_after_failures"] is None
    assert any(g["id"] == "login_outcome_unknown" and "names no account" in g["statement"] for g in c["gaps"])
    assert assess_severity(c)["rule"].startswith("M2") and assess_confidence(c)["confidence"] != "high"


def test_a_source_ip_search_does_not_prove_there_was_no_success(alert):
    fails = attack()[:-1]
    other = ev("2026-11-18T09:45:03.000Z", "auth_success", "j.mehta", "198.51.100.99", 70)   # unseen by this search
    c = correlate(alert, [search({"source": "all", "src_ip": ATTACKER, "limit": 200}, fails)], [])
    assert other not in fails and c["signals"]["success_after_failures"] is None


def test_an_unknown_outcome_is_a_gap_and_forbids_high_confidence(alert):
    narrow = {"source": "all", "src_ip": ATTACKER, "start": "2026-11-18T09:00:00Z", "end": "2026-11-18T09:42:00Z"}
    c = correlate(alert, [search(narrow, attack()[:-1])], [])
    assert any(g["id"] == "login_outcome_unknown" for g in c["gaps"])
    assert c["suggested_follow_ups"][0].startswith("search_logs source=wazuh account=j.mehta")
    assert assess_confidence(c)["confidence"] != "high"


def test_an_earlier_office_login_is_not_taken_for_the_compromise(alert):
    evs = [ev("2026-11-18T08:45:01.000Z", "auth_failure", "j.mehta", OFFICE, 4),
           ev("2026-11-18T08:45:09.000Z", "auth_success", "j.mehta", OFFICE, 5)] + attack()
    c = correlate(alert, [search(ACCOUNT_SEARCH, evs)], [])
    d = facts(c)["success_after_failures"]["data"]
    assert d["success_time"] == "2026-11-18T09:42:17.512Z" and d["src_ip"] == ATTACKER and d["failures_before"] == 50
    phases = {t["evidence_ref"]: t["phase"] for t in c["timeline"]}
    assert phases["wazuh_alerts.jsonl#L5"] == "baseline" and phases[SUCCESS] == "compromise"


def test_a_login_on_another_host_is_not_the_success():
    alert = load_alert(ROOT / "data" / "scenarios" / "failures_only" / "alert.json")
    evs = attack()[:-1] + [ev("2026-11-18T09:59:30.000Z", "auth_success", "j.mehta", OFFICE, 80, host="db-fin-01",
                              dst="10.20.5.30")]
    c = correlate(alert, [search(ACCOUNT_SEARCH, evs)], [])
    assert c["signals"]["success_after_failures"] is False and assess_severity(c)["rule"].startswith("L1")


@pytest.mark.parametrize("obs", [{"success_time": 1794994937.5}, {"failure_window_start": 1794994262},
                                 {"failure_window_end": True}])
def test_non_string_observation_times_do_not_crash(alert, obs):
    changed = {**alert, "observations": {**alert["observations"], **obs}}
    c = correlate(changed, [search(ACCOUNT_SEARCH, attack())], [])
    assert c["signals"]["success_after_failures"] is True


def test_tool_results_used_counts_only_evidence_tools(alert):
    ctx = RunContext("INV-TEST-REV", alert)
    call_tool(GET_ALERT, {"alert_id": alert["alert_id"]}, ctx)
    call_tool(SEARCH_LOGS, {"source": "wazuh", "account": "a.rao"}, ctx)
    c = correlate(alert, ctx.evidence_results, ctx.tool_calls)
    assert c["evidence_basis"]["tool_results_used"] == 1


# ------------------------------------------------------------------------- the wrapper
def test_a_ref_carried_by_the_alert_is_not_citable(alert):
    forged = {**alert, "observations": {**alert["observations"], "evidence_ref": "wazuh_alerts.jsonl#L999"}}
    ctx = RunContext("INV-TEST-FORGED", forged)
    _, entry = call_tool(GET_ALERT, {"alert_id": alert["alert_id"]}, ctx)
    assert entry["status"] == "ok" and ctx.evidence_refs == {} and entry["evidence_refs"] == []


def test_a_slow_submission_is_never_committed_after_it_returned(alert, monkeypatch):
    """write_internal handlers run inline: there is no background thread left to store findings later."""
    import soc_agent.tools.assessment as asm
    ctx = make_ctx(alert)
    f = valid(ctx)
    real = asm.run_correlation
    monkeypatch.setattr(asm, "run_correlation", lambda c: (time.sleep(0.4), real(c))[1])
    ctx.tool_timeout_s = 0.1
    out, entry = call_tool(SUBMIT_FINDINGS, f, ctx)
    assert entry["status"] == "ok" and ctx.findings == f                   # finished inline, not "timeout"
    assert threading.active_count() < 50


# ------------------------------------------------------------------------- findings
def make_ctx(alert, faults=None, lookup_dst=True):
    ctx = RunContext("INV-TEST-REV2", alert, plan=build_mock_plan(alert), faults=faults or {}, tool_timeout_s=0.3)
    calls = [(SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta", "host": "fin-app-01",
                            "start": "2026-11-11T00:00:00Z", "end": "2026-11-18T12:00:00Z", "limit": 200}),
             (SEARCH_LOGS, {"source": "all", "src_ip": ATTACKER, "limit": 200}), (LOOKUP_IP, {"ip": ATTACKER}),
             (GET_ASSET_CONTEXT, {"host": "fin-app-01"}), (GET_ASSET_CONTEXT, {"account": "j.mehta"}),
             (SEARCH_LOGS, {"source": "all", "host": "fin-app-01", "start": "2026-11-18T09:42:17Z"})]
    if lookup_dst:
        calls.append((LOOKUP_IP, {"ip": OUTBOUND}))
    for spec, args in calls:
        call_tool(spec, args, ctx)
    return ctx


def valid(ctx):
    c = correlate(ctx.alert, ctx.evidence_results, ctx.tool_calls)
    return build_mock_findings(c, rubric(c), ctx.plan, ctx.alert)


def rejected(ctx, f, needle):
    out, entry = call_tool(SUBMIT_FINDINGS, f, ctx)
    assert entry["status"] == "rejected", out
    assert needle in json.dumps(out), json.dumps(out)[:2000]


@pytest.mark.parametrize("where, text", [
    ("alternative_explanations", f"{ATTACKER} is a known malicious scanner per threat intel."),
    ("confidence_rationale", f"Threat intel says {ATTACKER} is malicious."),
    ("next_step_rationale", f"intel reputation: {ATTACKER} is malicious"),
])
def test_reputation_in_free_text_after_a_failed_lookup_is_refused(alert, where, text):
    ctx = make_ctx(alert, faults={"lookup_ip": "timeout"})
    f = valid(ctx)
    if where == "alternative_explanations":
        f["alternative_explanations"].append(text)
    elif where == "confidence_rationale":
        f["confidence_rationale"] = text
    else:
        f["recommended_next_steps"][0]["rationale"] = text
    rejected(ctx, f, f"lookup_ip for {ATTACKER} failed or timed out")


def test_stating_unknown_reputation_in_a_rationale_is_fine(alert):
    ctx = make_ctx(alert, faults={"lookup_ip": "timeout"})
    f = valid(ctx)
    f["confidence_rationale"] = f"Medium: lookup_ip for {ATTACKER} timed out, so its reputation is unknown."
    out, entry = call_tool(SUBMIT_FINDINGS, f, ctx)
    assert entry["status"] == "ok", out


@pytest.mark.parametrize("statement", [f"{OUTBOUND} is malicious.", f"{OUTBOUND}, a known C2 server for a botnet."])
def test_verdict_about_an_ip_that_was_never_looked_up_is_refused(alert, statement):
    ctx = make_ctx(alert, lookup_dst=False)
    f = valid(ctx)
    f["related_events"].append({"statement": statement, "evidence_refs": ["tshark_sessions.csv#row62"]})
    rejected(ctx, f, f"lookup_ip returned no intelligence for {OUTBOUND} in this run")


@pytest.mark.parametrize("action", ["Rotate j.mehta credentials and log out all sessions.",
                                    "Take fin-app-01 offline and remove the backup_svc account.",
                                    "Suspend j.mehta pending review."])
def test_more_containment_wording_cannot_be_labelled_investigative(alert, action):
    ctx = make_ctx(alert)
    f = valid(ctx)
    f["recommended_next_steps"].append({"action": action, "type": "investigative", "rationale": "Contain it.",
                                        "requires_approval": False})
    rejected(ctx, f, "is a containment action")


def test_saying_rubric_is_not_enough_to_disagree(alert):
    ctx = make_ctx(alert)
    f = valid(ctx)
    f.update(severity="high", severity_rationale="MOCK intel aside, I disagree with the rubric.",
             severity_evidence_refs=[SUCCESS])
    rejected(ctx, f, "mention the rubric and its level (critical)")


def test_placeholder_unknowns_do_not_count(alert):
    ctx = make_ctx(alert, faults={"lookup_ip": "timeout"})
    f = valid(ctx)
    f["unknowns"] = ["None."]
    rejected(ctx, f, "remove placeholder entries such as 'None.'")


def test_internal_source_outside_the_baseline_does_not_lower_severity():
    from test_severity import corr
    s = assess_severity(corr(source_ip="10.20.9.9", source_ip_internal=True, source_in_baseline=False))
    f = next(x for x in s["factors"] if "internal" in x["factor"])
    assert f["points"] == 0 and "lateral movement" in f["factor"]


def test_a_rationale_problem_points_at_the_field_that_holds_its_refs(alert):
    """Live NVIDIA run INV-20261121-A62EAB3F: the model wrote the intel ref into severity_rationale's TEXT four times,
    because the problem named only severity_rationale and the hint said to keep every other field unchanged."""
    ctx = make_ctx(alert)
    f = valid(ctx)
    f["severity_rationale"] = ("Critical severity per rubric: success after brute force and sudo on a high-criticality "
                               f"host. MOCK intel: {ATTACKER} classified malicious per ip_reputation.json#{ATTACKER}.")
    f["severity_evidence_refs"] = [SUCCESS, "inventory.json#hosts/fin-app-01"]
    out, entry = call_tool(SUBMIT_FINDINGS, f, ctx)
    assert entry["status"] == "rejected"
    assert (f'add "ip_reputation.json#{ATTACKER}" to severity_evidence_refs (writing it in the text is not citing)'
            in out["problems"][0])
    assert "severity_evidence_refs" in out["hint"] and "severity_rationale" in out["hint"]
    f["severity_evidence_refs"].append(f"ip_reputation.json#{ATTACKER}")          # the fix the message asks for
    out, entry = call_tool(SUBMIT_FINDINGS, f, ctx)
    assert entry["status"] == "ok", out


# ------------------------------------- replay of real NVIDIA output (benign scenario)
def replay_benign():
    from soc_agent.tools.evidence import EVIDENCE_TOOLS
    fx = json.loads((ROOT / "tests" / "fixtures" / "nvidia_benign_findings.json").read_text())
    alert = load_alert(ROOT / "data" / "scenarios" / "benign" / "alert.json")
    ctx = RunContext("INV-TEST-REPLAY", alert, plan=fx["plan"], data_dir=ROOT / "data" / "scenarios" / "benign")
    specs = {s.name: s for s in EVIDENCE_TOOLS}
    for c in fx["calls"]:
        assert call_tool(specs[c["tool"]], c["arguments"], ctx)[1]["status"] == "ok"
    return ctx, copy.deepcopy(fx["findings"])


def test_recorded_nvidia_benign_findings_are_now_rejected_for_their_analytical_errors():
    ctx, f = replay_benign()
    out, entry = call_tool(SUBMIT_FINDINGS, f, ctx)
    text = json.dumps(out)
    assert entry["status"] == "rejected"
    assert "mitre T1110: Brute Force needs at least 10 failed logins" in text and "this run shows 4" in text
    assert "mitre T1110.001:" in text
    assert "mitre T1021.004: the cited login(s) came from 10.20.1.45, which is in the account's baseline" in text
    assert "hypothesis H2 (benign): refuted contradicts the deterministic facts" in text


def test_recorded_nvidia_benign_findings_pass_once_corrected_and_a_kept_view_is_recorded():
    ctx, f = replay_benign()
    f["mitre"] = []
    for h in f["hypotheses"]:                                  # the model keeps H2 refuted but addresses the facts
        if h["id"] == "H2":
            h["reasoning"] += " Although 10.20.1.45 is in the account's baseline, I keep this refuted."
    out, entry = call_tool(SUBMIT_FINDINGS, f, ctx)
    assert entry["status"] == "ok", out
    ch = out["severity_check"]["hypothesis_challenges"]
    assert ch == [{"id": "H2", "status": "refuted", "rubric_rule": "L2", "addressed": True, "accepted_after_hint": None}]
    assert out["severity_check"]["agrees"] is False                   # medium vs rubric low: recorded, not overwritten


def test_a_field_with_problems_is_not_reused_from_the_previous_attempt(alert):
    """Live NVIDIA run INV-20261121-3DA81BB9: the model left out exactly the fields it had to fix, the carry-over
    reused the faulty versions, and the same problems came back on every attempt."""
    ctx = make_ctx(alert)
    good = valid(ctx)
    bad = copy.deepcopy(good)
    bad["related_events"][0]["evidence_refs"] = ["wazuh_alerts.jsonl#L999"]
    assert call_tool(SUBMIT_FINDINGS, bad, ctx)[1]["status"] == "rejected"
    out, entry = call_tool(SUBMIT_FINDINGS, {k: v for k, v in good.items() if k != "related_events"}, ctx)
    assert entry["status"] == "rejected" and "'related_events' is a required property" in json.dumps(out)
    assert "Not taken from your previous submission because they had problems: related_events" in json.dumps(out)
    out, entry = call_tool(SUBMIT_FINDINGS, {k: v for k, v in good.items() if k != "mitre"}, ctx)   # sent fixed
    assert entry["status"] == "ok" and "taken from your previous submission: mitre" in json.dumps(out)


def test_competing_benign_hypotheses_need_one_supported_not_all():
    from soc_agent.scenarios import check_expected, load_scenario
    exp = load_scenario("benign").expected
    plan = {"hypotheses": [{"id": "H1", "benign": False}, {"id": "H2", "benign": True}, {"id": "H3", "benign": True}]}

    def assessment(statuses):
        return {"findings": {"severity": "low", "confidence": "medium", "mitre": [], "unknowns": [],
                             "severity_evidence_refs": ["wazuh_alerts.jsonl#L10", "inventory.json#accounts/j.mehta"],
                             "hypotheses": [{"id": i, "status": st, "evidence_refs": []} for i, st in statuses]},
                "rubric": {"severity": {"severity": "low"}}, "gaps": [], "conflicts": []}
    ok = assessment([("H1", "refuted"), ("H2", "supported"), ("H3", "undetermined")])
    assert not any("benign" in p for p in check_expected(ok, exp, plan, mock=False))
    bad = assessment([("H1", "supported"), ("H2", "refuted"), ("H3", "undetermined")])
    assert any("no benign hypothesis is supported" in p for p in check_expected(bad, exp, plan, mock=False))
    comp = load_scenario("compromise").expected                        # compromise: none may be supported
    assert any("H2 is supported" in p for p in check_expected(ok, comp, plan, mock=False))


# ----------------------------------- from the full NVIDIA scenario run (2026-11-21 05:01 UTC)
def test_ssh_lateral_movement_is_refused_for_an_external_login(alert):
    """INV-20261121-E659FC0A: the attacker's internet login was tagged T1021.004 (lateral movement) and not T1078."""
    ctx = make_ctx(alert)
    f = valid(ctx)
    f["mitre"] = [m for m in f["mitre"] if m["technique_id"] != "T1078"] + [
        {"technique_id": "T1021.004", "name": "Remote Services: SSH", "evidence_refs": [SUCCESS],
         "justification": "Successful SSH login after the brute force."}]
    rejected(ctx, f, "the cited login came from the external address 203.0.113.77. A login with valid credentials "
                     "from outside is T1078 Valid Accounts")


def test_high_for_failures_without_a_success_is_rejected_with_the_facts():
    """INV-20261121-856D23C2: 50 failures, no success, agent said high citing the rubric's high rule anyway."""
    from soc_agent.tools.evidence import EVIDENCE_TOOLS
    alert = load_alert(ROOT / "data" / "scenarios" / "failures_only" / "alert.json")
    ctx = RunContext("INV-TEST-FO", alert, plan=build_mock_plan(alert), data_dir=ROOT / "data" / "scenarios" / "failures_only")
    specs = {s.name: s for s in EVIDENCE_TOOLS}
    for tool, args in [("search_logs", {"source": "all", "account": "j.mehta", "limit": 200}),
                       ("search_logs", {"source": "all", "src_ip": ATTACKER, "limit": 200}),
                       ("lookup_ip", {"ip": ATTACKER}), ("get_asset_context", {"host": "fin-app-01"}),
                       ("get_asset_context", {"account": "j.mehta"})]:
        call_tool(specs[tool], args, ctx)
    f = valid(ctx)
    f["severity_evidence_refs"] = [r for r in f["severity_evidence_refs"] if not r.startswith("ip_reputation")]
    f.update(severity="high", severity_rationale="The rubric says low, but 50 failures on a critical host is high.")
    rejected(ctx, f, "no successful login after the failures was found (fact success_after_failures)")
    f.update(severity="medium", severity_rationale="The rubric says low; I rate it medium: 50 failures on a critical, "
                                                   "internet-exposed host deserve a hardening review.")
    out, entry = call_tool(SUBMIT_FINDINGS, f, ctx)                  # one level of discretion is fine
    assert entry["status"] == "ok", out
    assert out["severity_check"]["agrees"] is False and out["severity_check"]["rubric_severity"] == "low"


def test_format_errors_do_not_use_up_the_content_attempts(alert):
    """INV-20261121-252F58C4: four format errors burned the content attempts of a correct assessment."""
    ctx = make_ctx(alert)
    f = valid(ctx)
    bad = copy.deepcopy(f)
    bad["containment"][0]["requires_approval"] = True                      # a format (schema) error
    for _ in range(3):
        out, entry = call_tool(SUBMIT_FINDINGS, bad, ctx)
        assert entry["status"] == "rejected" and out["error"].startswith("Invalid arguments")
    out, entry = call_tool(SUBMIT_FINDINGS, f, ctx)
    assert entry["status"] == "ok", out                                      # content attempt 1 of 5
    ctx2 = make_ctx(alert)
    for _ in range(5):                                                       # MAX_FORMAT_REJECTIONS
        call_tool(SUBMIT_FINDINGS, bad, ctx2)
    out, _ = call_tool(SUBMIT_FINDINGS, f, ctx2)                             # the format budget is bounded too
    assert "Too many findings submissions" in out["error"]


def test_schema_messages_say_the_limit_and_the_expected_shape(alert):
    ctx = make_ctx(alert)
    f = valid(ctx)
    f["timeline"][0]["statement"] = "x" * 609
    f["severity_justification"] = ["Critical because of sudo."]
    out, _ = call_tool(SUBMIT_FINDINGS, f, ctx)
    text = json.dumps(out)
    assert "maximum 600 characters; shorten it" in text and "send a JSON object here" in text


def test_a_wazuh_search_starting_after_the_first_attempts_gives_no_false_tshark_conflict(alert):
    """INV-20261121-E0D07DE0: Wazuh searched from 09:30:00 (after two a.rao failures), tshark without a window:
    53 sessions vs 52 attempts was reported as a conflict on consistent data."""
    from soc_agent.correlate import correlate
    ctx = RunContext("INV-TEST-TW", alert)
    call_tool(SEARCH_LOGS, {"source": "wazuh", "host": "fin-app-01", "src_ip": ATTACKER, "start": "2026-11-18T09:30:00Z",
                            "end": "2026-11-18T09:50:00Z", "limit": 200}, ctx)
    call_tool(SEARCH_LOGS, {"source": "tshark", "src_ip": ATTACKER, "limit": 200}, ctx)
    c = correlate(alert, ctx.evidence_results, ctx.tool_calls)
    assert c["conflicts"] == [] and c["signals"]["tshark_wazuh"] == "not_comparable"


# ----------------------------------- from the second full NVIDIA scenario run (2026-11-21)
def test_a_sub_technique_satisfies_a_required_technique():
    """INV-20261121-89A284B1 used T1078.003 (Valid Accounts: Local Accounts), a more specific form of T1078."""
    from soc_agent.scenarios import check_expected, load_scenario
    exp = load_scenario("compromise").expected
    base = {"severity": "critical", "confidence": "medium", "unknowns": [], "hypotheses": [],
            "severity_evidence_refs": ["wazuh_alerts.jsonl#L64", "wazuh_alerts.jsonl#L65", "wazuh_alerts.jsonl#L66"]}
    a = {"rubric": {"severity": {"severity": "critical"}}, "gaps": [], "conflicts": []}
    for used, ok in ((["T1078.003"], True), (["T1078"], True), (["T1021.004"], False)):
        a["findings"] = {**base, "mitre": [{"technique_id": t} for t in used]}
        assert (not any("T1078" in p for p in check_expected(a, exp, None, mock=False))) is ok


def test_a_fact_id_sent_as_a_ref_names_the_facts_real_refs(alert):
    """INV-20261121-FA096A9D cited 'source_ip_baseline' (a fact id) as an evidence_ref three times."""
    ctx = make_ctx(alert)
    f = valid(ctx)
    f["hypotheses"][0]["evidence_refs"] = ["source_ip_baseline"]
    out, entry = call_tool(SUBMIT_FINDINGS, f, ctx)
    assert entry["status"] == "rejected" and out["error"].startswith("Invalid arguments")      # a format rejection
    assert ("'source_ip_baseline' is the id of a correlate_evidence fact, not an evidence_ref; cite that fact's "
            "evidence_refs instead: inventory.json#accounts/j.mehta") in out["problems"][0]


def test_citing_intel_for_an_internal_ip_names_what_to_cite_instead():
    """INV-20261121-FA096A9D cited ip_reputation.json#10.20.1.45: lookup_ip returns no ref for internal addresses."""
    from soc_agent.tools.evidence import EVIDENCE_TOOLS
    alert = load_alert(ROOT / "data" / "scenarios" / "benign" / "alert.json")
    ctx = RunContext("INV-TEST-INT", alert, plan=build_mock_plan(alert), data_dir=ROOT / "data" / "scenarios" / "benign")
    specs = {s.name: s for s in EVIDENCE_TOOLS}
    for tool, args in [("search_logs", {"source": "all", "account": "j.mehta", "limit": 200}),
                       ("lookup_ip", {"ip": OFFICE}), ("get_asset_context", {"account": "j.mehta"})]:
        call_tool(specs[tool], args, ctx)
    f = valid(ctx)
    f["source_ip_intelligence"] = [{"statement": f"MOCK intel: {OFFICE} is internal.",
                                    "evidence_refs": [f"ip_reputation.json#{OFFICE}"]}]
    rejected(ctx, f, f"lookup_ip found no intel record for {OFFICE}, so there is no ip_reputation ref to cite; for the "
                     "source IP cite the refs of the facts source_ip_type / source_ip_baseline: wazuh_alerts.jsonl#L")


def test_uncomparable_tshark_and_wazuh_get_a_concrete_follow_up():
    """INV-20261121-709F31A2 never searched tshark over the attack window, so the conflict could not be found."""
    alert = load_alert(ROOT / "data" / "scenarios" / "conflicting" / "alert.json")
    ctx = RunContext("INV-TEST-CF", alert, data_dir=ROOT / "data" / "scenarios" / "conflicting")
    call_tool(SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta", "limit": 200}, ctx)
    call_tool(SEARCH_LOGS, {"source": "tshark", "host": "fin-app-01", "start": "2026-11-18T09:42:17Z",
                            "event_type": "network_session"}, ctx)
    c = correlate(alert, ctx.evidence_results, ctx.tool_calls)
    fu = [x for x in c["suggested_follow_ups"] if "compared with Wazuh attempts" in x]
    assert fu and fu[0].startswith(f"search_logs source=all src_ip={ATTACKER} start=2026-11-18T09:30:02Z")
    # making that call reveals the conflict
    call_tool(SEARCH_LOGS, {"source": "all", "src_ip": ATTACKER, "start": "2026-11-18T09:30:02Z",
                            "end": "2026-11-18T09:43:17Z", "limit": 200}, ctx)
    c = correlate(alert, ctx.evidence_results, ctx.tool_calls)
    assert [x["id"] for x in c["conflicts"]] == ["tshark_vs_wazuh"]


def test_truncation_note_says_how_to_see_the_latest_events(alert):
    """INV (tool_failure, 2026-11-21 06:2x): 52 matches, the default limit 50 cut off the success (L64) and the sudo;
    the model repeated the same search because the note said to narrow the filters."""
    ctx = RunContext("INV-TEST-TRUNC", alert)
    out, _ = call_tool(SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta", "host": "fin-app-01",
                                     "start": "2026-11-18T09:20:00Z", "end": "2026-11-18T10:00:00Z"}, ctx)
    note = next(n for n in out["notes"] if n.startswith("Only the earliest"))
    assert "the LATEST 2 are missing (a successful login" in note and "call again with limit=200" in note
    assert SUCCESS not in ctx.evidence_refs


def test_too_few_sessions_is_provable_from_an_account_only_search():
    """Third NVIDIA suite, conflicting: the model searched Wazuh for the account and tshark for the IP. 51 attempts
    for j.mehta alone already need more than 7 sessions x 6 attempts, so the conflict is reported."""
    alert = load_alert(ROOT / "data" / "scenarios" / "conflicting" / "alert.json")
    ctx = RunContext("INV-TEST-LB", alert, data_dir=ROOT / "data" / "scenarios" / "conflicting")
    call_tool(SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta", "start": "2026-11-18T09:31:02Z",
                            "end": "2026-11-18T10:42:17Z", "limit": 200}, ctx)
    call_tool(SEARCH_LOGS, {"source": "tshark", "src_ip": ATTACKER, "limit": 200}, ctx)
    c = correlate(alert, ctx.evidence_results, ctx.tool_calls)
    conflict = next(x for x in c["conflicts"] if x["id"] == "tshark_vs_wazuh")
    assert conflict["statement"].startswith(f"At least 51 Wazuh login attempt(s) from {ATTACKER} (the Wazuh searches")
    assert "but only 7 tshark SSH session(s)" in conflict["statement"]


def test_an_account_only_search_never_proves_consistency(alert):
    """The same lower bound on consistent data (main case: 51 attempts for j.mehta, 54 sessions) stays uncompared."""
    ctx = RunContext("INV-TEST-LB2", alert)
    call_tool(SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta", "start": "2026-11-18T09:00:00Z",
                            "end": "2026-11-18T10:42:17Z", "limit": 200}, ctx)
    call_tool(SEARCH_LOGS, {"source": "tshark", "src_ip": ATTACKER, "limit": 200}, ctx)
    c = correlate(alert, ctx.evidence_results, ctx.tool_calls)
    assert c["signals"]["tshark_wazuh"] == "not_comparable" and c["conflicts"] == []


@pytest.mark.parametrize("change", [lambda f: f.pop("severity_justification"),
                                    lambda f: f.update(severity_justification=["Critical because of sudo."])])
def test_severity_justification_mixups_get_an_explicit_note(alert, change):
    """A live model omitted severity_justification three times and sent it as a string once (it is not the string
    field severity_rationale)."""
    from soc_agent.tools.assessment import SEVERITY_JUSTIFICATION_NOTE
    ctx = make_ctx(alert)
    f = valid(ctx)
    change(f)
    out, entry = call_tool(SUBMIT_FINDINGS, f, ctx)
    assert entry["status"] == "rejected" and SEVERITY_JUSTIFICATION_NOTE in out["notes"]


def test_prompt_rubric_puts_the_benign_rule_before_medium():
    """Final NVIDIA suite: the prompt described medium as 'source internal / known for the user', which is exactly
    the benign case; the code checks the benign rule (L2) first. The prompt now says so."""
    from soc_agent.prompts import ASSESSOR_SYSTEM
    low, medium = ASSESSOR_SYSTEM.index("    low:      failures"), ASSESSOR_SYSTEM.index("    medium:   any other")
    assert low < medium and "critical, high, low (benign), medium" in ASSESSOR_SYSTEM
    assert "This holds even on a high-criticality host" in ASSESSOR_SYSTEM


def test_run_scenarios_retries_once_after_a_rate_limit(monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("rs", ROOT / "scripts" / "run_scenarios.py")
    rs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rs)
    rows = iter([{"investigation_id": "INV-1", "error": "RuntimeError: HTTP 429: Too Many Requests"},
                 {"investigation_id": "INV-2", "error": None}])
    monkeypatch.setattr(rs.time, "sleep", lambda s: None)
    settings = type("S", (), {"is_mock": False})()
    row = rs._with_retry(lambda: next(rows), settings, "benign")
    assert row["investigation_id"] == "INV-2" and row["note"] == "retried once after HTTP 429; first run INV-1"
