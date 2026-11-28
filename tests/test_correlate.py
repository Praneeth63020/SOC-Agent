"""Day 3 deterministic correlation (correlate.py) and the correlate_evidence tool. Offline: tools are
called directly through the same wrapper; no Hermes, no LLM."""
import json
from pathlib import Path

import pytest

from soc_agent.alerts import load_alert
from soc_agent.correlate import PHASES, condense_timeline, correlate
from soc_agent.schemas import load_tool_schema, problems
from soc_agent.tools.assessment import CORRELATE_EVIDENCE
from soc_agent.tools.base import RunContext, call_tool
from soc_agent.tools.evidence import GET_ASSET_CONTEXT, LOOKUP_IP, SEARCH_LOGS

ROOT = Path(__file__).resolve().parent.parent
SCEN = ROOT / "data" / "scenarios"
ATTACKER, OUTBOUND, OFFICE = "203.0.113.77", "198.51.100.23", "10.20.1.45"


def gather(alert, data_dir=ROOT / "data", faults=None, lookup_dst=True, account_context=True, calls=None):
    """The evidence calls the analyze script makes, through the real wrapper; returns (ctx, correlation)."""
    ctx = RunContext("INV-TEST-CORR", alert, data_dir=Path(data_dir), faults=faults or {}, tool_timeout_s=0.3)
    e = alert["entities"]
    default = [
        (SEARCH_LOGS, {"source": "wazuh", "account": e["account"], "host": e["host"],
                       "start": "2026-11-11T00:00:00Z", "end": "2026-11-18T12:00:00Z", "limit": 200}),
        (SEARCH_LOGS, {"source": "all", "src_ip": e["src_ip"], "limit": 200}),
        (LOOKUP_IP, {"ip": e["src_ip"]}),
        (GET_ASSET_CONTEXT, {"host": e["host"]}),
        *([(GET_ASSET_CONTEXT, {"account": e["account"]})] if account_context else []),
        (SEARCH_LOGS, {"source": "all", "host": e["host"], "start": alert["timestamp"][:19] + "Z", "limit": 200}),
        *([(LOOKUP_IP, {"ip": OUTBOUND})] if lookup_dst else []),
    ]
    for spec, args in calls if calls is not None else default:
        call_tool(spec, args, ctx)
    return ctx, correlate(alert, ctx.evidence_results, ctx.tool_calls)


@pytest.fixture(scope="module")
def main_case():
    alert = load_alert(ROOT / "data" / "alerts" / "account_compromise.json")
    return gather(alert)


def facts(corr):
    return {f["id"]: f for f in corr["facts"]}


# ---------------------------------------------------------------------------- timeline
def test_timeline_is_sorted_with_phases(main_case):
    _, c = main_case
    tl = c["timeline"]
    assert tl and [t["time"] for t in tl] == sorted(t["time"] for t in tl)
    assert {t["phase"] for t in tl} <= set(PHASES)
    by_ref = {t["evidence_ref"]: t["phase"] for t in tl}
    assert by_ref["wazuh_alerts.jsonl#L2"] == by_ref["wazuh_alerts.jsonl#L3"] == "baseline"   # office logins
    assert by_ref["wazuh_alerts.jsonl#L9"] == "attack"                                       # a.rao, first failure
    assert by_ref["tshark_sessions.csv#row8"] == "attack"           # its TCP session opened 0.6 s before it
    assert by_ref["wazuh_alerts.jsonl#L63"] == "attack"                                      # last j.mehta failure
    assert by_ref["wazuh_alerts.jsonl#L64"] == by_ref["tshark_sessions.csv#row61"] == "compromise"
    for ref in ("wazuh_alerts.jsonl#L65", "wazuh_alerts.jsonl#L66", "tshark_sessions.csv#row62"):
        assert by_ref[ref] == "post_compromise"
    assert set(tl[0]) == {"time", "phase", "source", "event_type", "account", "host", "src_ip", "dst_ip", "summary",
                          "evidence_ref"}
    # unrelated noise (scanner against web-portal-01, p.nair on db-fin-01) is not in the timeline
    assert not any(t["src_ip"] == "192.0.2.44" or t["account"] == "p.nair" for t in tl)


def test_condensed_timeline_keeps_first_and_last_refs(main_case):
    _, c = main_case
    rows = condense_timeline(c["timeline"])
    fails = next(r for r in rows if r["event_type"] == "auth_failure" and r["account"] == "j.mehta")
    assert fails["count"] == 50 and fails["evidence_refs"] == ["wazuh_alerts.jsonl#L12", "wazuh_alerts.jsonl#L63"]
    assert sum(r["count"] for r in rows) == len(c["timeline"])


def test_only_this_runs_evidence_is_used(alert):
    ctx = RunContext("INV-TEST-EMPTY", alert)
    c = correlate(alert, ctx.evidence_results, ctx.tool_calls)    # nothing gathered: nothing is read from disk
    assert c["timeline"] == [] and c["evidence_basis"]["tool_results_used"] == 0
    assert c["signals"]["success_after_failures"] is None
    assert {g["key_source"] for g in c["gaps"]} == {"auth_logs", "network_sessions", "ip_intel", "host_context",
                                                    "account_context"}
    # one narrow search: only what it returned is correlated
    ctx2, c2 = gather(alert, calls=[(SEARCH_LOGS, {"source": "wazuh", "account": "a.rao"})])
    assert {t["evidence_ref"] for t in c2["timeline"]} <= set(ctx2.evidence_refs)
    assert all(r in ctx2.evidence_refs for f in c2["facts"] for r in f["evidence_refs"])


# ------------------------------------------------------------------------------- facts
def test_failure_counts_per_account_and_source_ip(main_case):
    f = facts(main_case[1])
    assert f["failures_by_account"]["data"]["counts"] == {"j.mehta": 50, "a.rao": 3}
    assert f["failures_by_src_ip"]["data"]["counts"] == {ATTACKER: 53}
    assert f["failures_by_account"]["data"]["first"]["j.mehta"] == "2026-11-18T09:31:02.000Z"
    assert f["failures_by_account"]["data"]["last"]["j.mehta"] == "2026-11-18T09:41:55.000Z"


def test_success_after_failures(main_case):
    d = facts(main_case[1])["success_after_failures"]
    want = {"failures_before": 50, "same_ip": True, "seconds_after_last_failure": 22.5, "src_ip": ATTACKER}
    assert {k: d["data"][k] for k in want} == want
    assert d["evidence_refs"][0] == "wazuh_alerts.jsonl#L64"
    assert "1588.4 s" in facts(main_case[1])["login_session"]["statement"]


def test_baseline_check(main_case):
    f = facts(main_case[1])["source_ip_baseline"]
    assert f["data"]["in_baseline"] is False and f["data"]["usual_source_ips"] == [OFFICE]
    assert f["data"]["earlier_successes"] == 2
    assert {"inventory.json#accounts/j.mehta", "wazuh_alerts.jsonl#L2"} <= set(f["evidence_refs"])
    benign = load_alert(SCEN / "benign" / "alert.json")
    _, c = gather(benign, SCEN / "benign")
    assert c["signals"]["source_in_baseline"] is True and c["signals"]["source_ip_internal"] is True


def test_baseline_unknown_without_account_context_or_history(alert):
    _, c = gather(alert, account_context=False, calls=[(SEARCH_LOGS, {"source": "all", "src_ip": ATTACKER})])
    assert c["signals"]["source_in_baseline"] is None
    assert any(g["id"] == "account_context_not_queried" for g in c["gaps"])


def test_spraying_other_accounts_from_the_same_ip(main_case):
    f = facts(main_case[1])["other_accounts_targeted"]
    assert f["data"]["accounts"] == ["a.rao"] and f["data"]["counts"] == {"a.rao": 3}
    assert f["evidence_refs"] == ["wazuh_alerts.jsonl#L9", "wazuh_alerts.jsonl#L11"]


def test_post_login_events_and_destination_reputation(main_case):
    c = main_case[1]
    f = facts(c)
    assert f["post_compromise_privileged"]["data"]["count"] == 1
    assert f["post_compromise_privileged"]["evidence_refs"] == ["wazuh_alerts.jsonl#L65"]
    assert f["post_compromise_account_changes"]["evidence_refs"] == ["wazuh_alerts.jsonl#L66"]
    out = f["post_compromise_outbound"]
    assert out["data"]["destinations"] == [{"dst_ip": OUTBOUND, "sessions": 1, "bytes": 48213770, "dst_ports": [443],
                                            "classification": "suspicious", "reputation_status": "ok"}]
    assert out["evidence_refs"] == ["tshark_sessions.csv#row62"] and "intel" not in out["statement"]
    rep = f["outbound_destination_reputation"]                       # the reputation is its own MOCK-labelled fact
    assert rep["evidence_refs"] == [f"ip_reputation.json#{OUTBOUND}"] and "MOCK intel" in rep["statement"]


def test_unlooked_destination_is_a_gap(alert):
    _, c = gather(alert, lookup_dst=False)
    assert c["signals"]["post_outbound_external"][0]["reputation_status"] == "not_looked_up"
    assert c["sources"]["ip_intel"]["status"] == "partial"
    assert any(g["key_source"] == "ip_intel" and OUTBOUND in g["statement"] for g in c["gaps"])


def test_tshark_and_wazuh_counts_are_consistent(main_case):
    f = facts(main_case[1])["tshark_vs_wazuh"]
    assert f["data"] == {"status": "consistent", "wazuh_attempts": 54, "tshark_sessions": 54, "difference": 0}
    assert main_case[1]["conflicts"] == []


def test_fewer_sessions_than_attempts_is_a_conflict():
    alert = load_alert(SCEN / "conflicting" / "alert.json")
    _, c = gather(alert, SCEN / "conflicting")
    tw = facts(c)["tshark_vs_wazuh"]["data"]
    assert tw["status"] == "inconsistent" and tw["wazuh_attempts"] == 51 and tw["tshark_sessions"] == 7
    conflict = next(x for x in c["conflicts"] if x["id"] == "tshark_vs_wazuh")
    assert "only 7 tshark" in conflict["statement"] and conflict["possible_explanations"] and conflict["evidence_refs"]


def test_benign_retries_fit_into_few_sessions():
    alert = load_alert(SCEN / "benign" / "alert.json")
    _, c = gather(alert, SCEN / "benign")
    assert facts(c)["tshark_vs_wazuh"]["data"] == {"status": "consistent", "wazuh_attempts": 5,
                                                   "tshark_sessions": 2, "difference": 3}
    assert c["conflicts"] == [] and c["gaps"] == []


def test_a_narrow_search_is_not_compared(alert):
    """Counts are only compared when a search saw every attempt and session in the window."""
    _, c = gather(alert, calls=[(SEARCH_LOGS, {"source": "all", "account": "j.mehta", "limit": 200}),
                                (SEARCH_LOGS, {"source": "tshark", "src_ip": ATTACKER, "limit": 200})])
    assert c["signals"]["tshark_wazuh"] == "not_comparable"
    assert "tshark_vs_wazuh" not in facts(c) and c["conflicts"] == []


def test_alert_count_that_disagrees_with_the_logs_is_a_conflict(alert):
    changed = {**alert, "observations": {**alert["observations"], "failed_attempts": 40}}
    _, c = gather(changed)
    x = next(x for x in c["conflicts"] if x["id"] == "alert_vs_logs_failures")
    assert "reports 40 failed attempts" in x["statement"] and "show 50" in x["statement"]


def test_failures_without_success():
    alert = load_alert(SCEN / "failures_only" / "alert.json")
    _, c = gather(alert, SCEN / "failures_only")
    assert c["signals"]["success_after_failures"] is False and c["signals"]["failures_for_account"] == 50
    assert "post_compromise_privileged" not in facts(c)
    assert {t["phase"] for t in c["timeline"]} <= {"baseline", "attack", "post_attack"}


# -------------------------------------------------------------------------------- gaps
def test_gaps_from_failed_and_timed_out_tools(alert):
    _, c = gather(alert, faults={"lookup_ip": "timeout"})
    g = next(g for g in c["gaps"] if g["key_source"] == "ip_intel")
    assert g["id"] == "ip_intel_failed" and "timed out" in g["statement"] and "unknown" in g["statement"]
    assert c["signals"]["source_reputation"]["status"] == "failed"
    assert not any(r.startswith("ip_reputation") for f in c["facts"] for r in f["evidence_refs"])


def test_gaps_for_missing_tshark_and_host_not_in_inventory():
    alert = load_alert(SCEN / "incomplete" / "alert.json")
    ctx, c = gather(alert, SCEN / "incomplete", lookup_dst=False)
    assert [x["status"] for x in ctx.tool_calls if x["tool"] == "search_logs"] == ["ok", "error", "error"]
    ids = {g["id"] for g in c["gaps"]}
    assert {"network_sessions_failed", "host_context_missing"} <= ids
    assert "tshark_sessions.csv is unavailable" in next(g for g in c["gaps"] if g["id"] == "network_sessions_failed")[
        "statement"]
    assert c["signals"]["host_criticality"] is None and c["signals"]["post_privileged_actions"] == 1


def test_a_retried_call_that_succeeds_is_not_a_gap(alert):
    ctx = RunContext("INV-TEST-RETRY", alert, faults={"lookup_ip": "error"})
    call_tool(LOOKUP_IP, {"ip": ATTACKER}, ctx)
    ctx.faults = {}
    call_tool(LOOKUP_IP, {"ip": ATTACKER}, ctx)
    c = correlate(alert, ctx.evidence_results, ctx.tool_calls)
    assert c["sources"]["ip_intel"]["status"] == "ok"


# --------------------------------------------------------------------- the read tool
def test_correlate_evidence_tool_through_the_wrapper(main_case, alert):
    ctx, _ = main_case
    before = dict(ctx.evidence_refs)
    out, entry = call_tool(CORRELATE_EVIDENCE, {}, ctx)
    assert entry["status"] == "ok" and entry["permission"] == "read"
    assert problems(out, load_tool_schema("correlate_evidence", "output")) == []
    assert out["timeline_note"].startswith("116 timeline events condensed")   # 115 + the Day 4 injection line L68
    assert all("count" in r for r in out["timeline"])
    assert {k: ctx.evidence_refs[k] for k in before} == before        # refs keep the tool that first returned them
    assert ctx.evidence_results[-1]["tool"] != "correlate_evidence"     # derived output is not evidence
    assert entry["evidence_refs"] == []                              # ... and its refs are not newly citable
    out2, _ = call_tool(CORRELATE_EVIDENCE, {}, ctx)                  # correlating its own output changes nothing
    assert out2["facts"] == out["facts"]
    bad, entry = call_tool(CORRELATE_EVIDENCE, {"ip": ATTACKER}, ctx)
    assert entry["status"] == "rejected" and "'ip' was unexpected" in json.dumps(bad)


# ------------------------------------------------------------------ coverage follow-ups
def test_narrow_searches_become_gaps_with_concrete_follow_ups(alert):
    """What a live model once did: windows that miss the alert's failures, a post-login search filtered on
    port 22 (which hides sudo), no tshark. Each becomes a gap and a follow-up call the agent can make."""
    _, c = gather(alert, calls=[
        (SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta", "host": "fin-app-01",
                       "start": "2026-11-18T09:00:00Z", "end": "2026-11-18T09:31:02Z"}),
        (SEARCH_LOGS, {"source": "wazuh", "host": "fin-app-01", "src_ip": ATTACKER,
                       "start": "2026-11-18T09:42:17Z", "end": "2026-11-18T10:10:00Z"}),
        (SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta", "host": "fin-app-01", "dst_port": 22,
                       "start": "2026-11-18T09:42:17Z", "end": "2026-11-18T10:10:00Z"}),
    ])
    ids = {g["id"] for g in c["gaps"]}
    assert {"alert_window_not_covered", "post_login_not_covered", "network_sessions_not_queried"} <= ids
    assert "reports 50 failures; the searches returned 1" in next(
        g for g in c["gaps"] if g["id"] == "alert_window_not_covered")["statement"]
    fu = " | ".join(c["suggested_follow_ups"])
    assert "search_logs source=wazuh account=j.mehta start=2026-11-18T09:31:02Z end=2026-11-18T09:41:55Z" in fu
    assert "search_logs source=wazuh host=fin-app-01 start=2026-11-18T09:42:17Z" in fu
    assert f"search_logs source=tshark src_ip={ATTACKER}" in fu and "get_asset_context host=fin-app-01" in fu


def test_full_coverage_needs_no_follow_ups(main_case):
    assert main_case[1]["suggested_follow_ups"] == [] and main_case[1]["gaps"] == []


def test_a_truncated_search_makes_the_login_outcome_unknown(alert):
    """A live model searched with the default limit 50 and the success was cut off: that is not 'no success'."""
    from soc_agent.severity import assess_severity
    _, c = gather(alert, calls=[(SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta", "host": "fin-app-01"})])
    assert c["signals"]["success_after_failures"] is None
    assert any(g["id"] == "search_truncated" for g in c["gaps"])
    assert "repeat it with limit=200" in " ".join(c["suggested_follow_ups"])
    assert "outcome unknown" in facts(c)["success_after_failures"]["statement"]
    assert assess_severity(c)["rule"].startswith("M2")


# ------------------------------------------------- regression: correlation edge cases found in review
def _ev(t, et, acct, src, ref):
    return {"time": t, "source": "wazuh", "event_type": et, "account": acct, "host": "fin-app-01", "src_ip": src,
            "dst_ip": "10.20.5.17", "dst_port": None, "summary": "x", "evidence_ref": f"wazuh_alerts.jsonl#L{ref}"}


def _search(args, events, truncated=False):
    return {"seq": 1, "tool": "search_logs", "arguments": args, "result": {
        "query": args, "events": events, "total_matched": len(events), "returned": len(events), "truncated": truncated,
        "malformed_lines_skipped": 0, "counts": {"by_event_type": {}, "by_source": {}}, "first_time": None,
        "last_time": None, "notes": [], "data_label": "SYNTHETIC"}}


def test_an_old_stray_failure_does_not_hijack_the_attack_window(alert):
    evs = [_ev("2026-11-16T08:12:40.000Z", "auth_failure", "j.mehta", OFFICE, 2),       # a typo two days earlier
           _ev("2026-11-16T08:12:44.000Z", "auth_success", "j.mehta", OFFICE, 3)]
    evs += [_ev(f"2026-11-18T09:{31 + i // 6:02d}:{(i * 10) % 60:02d}.000Z", "auth_failure", "j.mehta", ATTACKER, 10 + i)
            for i in range(50)]
    evs += [_ev("2026-11-18T09:42:17.512Z", "auth_success", "j.mehta", ATTACKER, 64)]
    c = correlate(alert, [_search({"source": "wazuh", "account": "j.mehta", "start": "2026-11-11T00:00:00Z",
                                   "end": "2026-11-18T12:00:00Z"}, evs)], [])
    d = facts(c)["success_after_failures"]["data"]
    assert d["success_time"] == "2026-11-18T09:42:17.512Z" and d["failures_before"] == 50 and d["src_ip"] == ATTACKER
    assert c["signals"]["source_in_baseline"] is False                      # the 11-16 login is baseline
    phases = {t["evidence_ref"]: t["phase"] for t in c["timeline"]}
    assert phases["wazuh_alerts.jsonl#L2"] == phases["wazuh_alerts.jsonl#L3"] == "baseline"


def test_no_success_is_unknown_when_no_search_reached_the_alert_time(alert):
    from soc_agent.severity import assess_severity
    narrow = {"source": "wazuh", "account": "j.mehta", "start": "2026-11-18T09:00:00Z", "end": "2026-11-18T09:31:30Z"}
    c = correlate(alert, [_search(narrow, [_ev("2026-11-18T09:31:02.000Z", "auth_failure", "j.mehta", ATTACKER, 12)])],
                  [])
    assert c["signals"]["success_after_failures"] is None
    assert "outcome unknown" in facts(c)["success_after_failures"]["statement"]
    assert assess_severity(c)["rule"].startswith("M2")                       # not "failures without success" (low)



@pytest.mark.parametrize("scenario", ["compromise", "benign", "failures_only", "incomplete", "conflicting"])
def test_no_fact_pairs_an_intel_ref_with_an_unlabelled_statement(scenario):
    """A model copies a fact's (statement, refs) into a claim; every such pair must pass submit_findings' MOCK rule."""
    alert = load_alert(SCEN / scenario / "alert.json")
    _, c = gather(alert, SCEN / scenario)
    for f in c["facts"]:
        if any(r.startswith("ip_reputation.json#") for r in f["evidence_refs"]):
            assert "MOCK intel" in f["statement"], f
