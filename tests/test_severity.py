"""Day 3 severity and confidence rubric (severity.py) with crafted facts. Pure functions, offline."""
import pytest

from soc_agent.severity import BANDS, assess_confidence, assess_severity, rubric

R = "wazuh_alerts.jsonl#L"


def corr(gaps=(), conflicts=(), **sig):
    """A minimal correlation: the default is the main compromise case without post-login activity."""
    signals = {
        "auth_logs_available": True, "success_after_failures": True, "failures_for_account": 50,
        "failures_from_source": 53, "source_ip": "203.0.113.77", "source_ip_internal": False,
        "source_in_baseline": False, "seconds_last_failure_to_success": 22.5, "other_accounts_targeted": [],
        "host_found": True, "host_criticality": "high", "host_internet_exposed": True,
        "post_privileged_actions": 0, "post_account_changes": 0, "post_outbound_external": [],
        "source_reputation": {"status": "ok", "classification": "malicious", "score": 92}, "tshark_wazuh": "consistent",
        "refs": {"success": [R + "64"], "failures": [R + "12", R + "63"], "baseline": ["inventory.json#accounts/j.mehta"],
                 "source": [R + "64"], "host": ["inventory.json#hosts/fin-app-01"], "privileged": [R + "65"],
                 "account_changes": [R + "66"], "outbound": ["tshark_sessions.csv#row62"],
                 "source_reputation": ["ip_reputation.json#203.0.113.77"], "spraying": [R + "9"], "post_login": []},
    }
    signals.update(sig)
    return {"signals": signals, "gaps": list(gaps), "conflicts": list(conflicts)}


GAP_INTEL = {"id": "ip_intel_failed", "key_source": "ip_intel", "statement": "lookup_ip 203.0.113.77 timeout"}
GAP_TSHARK = {"id": "network_sessions_failed", "key_source": "network_sessions", "statement": "tshark missing"}
GAP_CVE = {"id": "search_cve_failed", "key_source": None, "statement": "search_cve error"}
CONFLICT = {"id": "tshark_vs_wazuh", "statement": "51 attempts but only 7 sessions", "evidence_refs": [R + "56"]}
OUT_BAD = [{"dst_ip": "198.51.100.23", "classification": "suspicious", "reputation_status": "ok"}]


@pytest.mark.parametrize("signals, level, rule", [
    ({"post_privileged_actions": 1, "post_account_changes": 1}, "critical", "C1"),
    ({"post_privileged_actions": 1}, "critical", "C1"),
    ({"host_criticality": None, "post_outbound_external": OUT_BAD}, "critical", "C2"),
    ({}, "high", "H1"),
    ({"failures_for_account": 3, "post_privileged_actions": 1}, "high", "H2"),
    ({"host_criticality": None, "post_account_changes": 1}, "high", "H2"),    # criticality unknown caps at high
    ({"host_criticality": "low", "post_privileged_actions": 1}, "high", "H2"),
    ({"source_ip": "10.20.1.45", "source_ip_internal": True, "source_in_baseline": True}, "medium", "M1"),  # brute
    ({"host_criticality": None}, "medium", "M1"),                                 # key evidence missing
    ({"source_in_baseline": None, "host_criticality": "medium"}, "medium", "M1"),
    ({"success_after_failures": None, "auth_logs_available": False}, "medium", "M2"),
    ({"success_after_failures": False}, "low", "L1"),
    ({"success_after_failures": False, "other_accounts_targeted": ["a.rao"]}, "low", "L1"),
    ({"success_after_failures": False, "failures_for_account": 0}, "low", "L0"),
    ({"failures_for_account": 4, "source_ip": "10.20.1.45", "source_ip_internal": True, "source_in_baseline": True,
      "source_reputation": {"status": "not_looked_up", "classification": None, "score": None}}, "low", "L2"),
], ids=["C1-sudo+useradd", "C1-sudo", "C2-outbound", "H1", "H2-few-failures", "H2-crit-unknown", "H2-low-crit",
        "M1-baseline-brute", "M1-crit-unknown", "M1-baseline-unknown", "M2-no-auth-logs", "L1", "L1-spray", "L0",
        "L2-benign"])
def test_severity_levels(signals, level, rule):
    s = assess_severity(corr(**signals))
    assert s["severity"] == level and s["rule"].startswith(rule), s["rule"]
    lo, hi = BANDS[level]
    assert lo <= s["score"] <= hi
    assert all({"factor", "effect", "points", "basis", "evidence_refs"} <= set(f) for f in s["factors"])


def test_benign_needs_few_failures_and_no_spraying():
    base = {"source_ip": "10.20.1.45", "source_ip_internal": True, "source_in_baseline": True}
    assert assess_severity(corr(failures_for_account=4, **base))["severity"] == "low"
    assert assess_severity(corr(failures_for_account=4, other_accounts_targeted=["a.rao"], **base))["severity"] == "medium"
    unknown_out = [{"dst_ip": "198.51.100.9", "classification": None, "reputation_status": "not_looked_up"}]
    assert assess_severity(corr(failures_for_account=4, post_outbound_external=unknown_out, **base))["severity"] == "medium"


def test_factors_cite_evidence_and_name_their_basis():
    s = assess_severity(corr(post_privileged_actions=1, post_account_changes=1, post_outbound_external=OUT_BAD,
                             other_accounts_targeted=["a.rao"]))
    by = {f["factor"].split(" ")[0]: f for f in s["factors"]}
    assert any(f["evidence_refs"] == [R + "65"] and f["basis"] == "logs" for f in s["factors"])
    intel = [f for f in s["factors"] if "MOCK intel" in f["basis"]]
    assert intel and all(any(r.startswith(("ip_reputation", "tshark")) for r in f["evidence_refs"]) for f in intel)
    assert by["Successful"]["evidence_refs"] == [R + "64", R + "12", R + "63"]
    assert s["score"] == 100 and not s["rests_on_mock_intel"]


def test_critical_only_through_mock_intel_is_flagged():
    s = assess_severity(corr(host_criticality=None, post_outbound_external=OUT_BAD))
    assert s["severity"] == "critical" and s["rests_on_mock_intel"] is True
    assert assess_confidence(corr(host_criticality=None, post_outbound_external=OUT_BAD), s)["confidence"] == "medium"


def test_score_orders_alerts_inside_a_band():
    plain = assess_severity(corr())
    more = assess_severity(corr(other_accounts_targeted=["a.rao"]))
    assert plain["severity"] == more["severity"] == "high" and more["score"] > plain["score"]


# ------------------------------------------------------------------------- confidence
@pytest.mark.parametrize("gaps, conflicts, level", [
    ([], [], "high"),
    ([GAP_INTEL], [], "medium"),
    ([GAP_CVE], [], "medium"),
    ([GAP_INTEL, {**GAP_INTEL, "id": "ip_intel_partial"}], [], "medium"),      # one key source, counted once
    ([GAP_INTEL, GAP_TSHARK], [], "low"),
    ([GAP_INTEL, GAP_CVE], [], "low"),
    ([], [CONFLICT], "low"),
], ids=["all-sources", "one-key-gap", "one-other-gap", "same-source-twice", "two-key-gaps", "key+other", "conflict"])
def test_confidence_levels(gaps, conflicts, level):
    c = assess_confidence(corr(gaps=gaps, conflicts=conflicts))
    assert c["confidence"] == level and c["reasons"]
    for g in gaps:
        assert any(g["statement"] in r for r in c["reasons"])
    for x in conflicts:
        assert any(x["statement"] in r for r in c["reasons"])


def test_confidence_is_independent_of_severity():
    low_sev = corr(success_after_failures=False)
    r = rubric(low_sev)
    assert r["severity"]["severity"] == "low" and r["confidence"]["confidence"] == "high"
    r = rubric(corr(post_privileged_actions=1, gaps=[GAP_INTEL, GAP_TSHARK]))
    assert r["severity"]["severity"] == "critical" and r["confidence"]["confidence"] == "low"


def test_routine_sudo_by_a_privileged_account_from_its_usual_source_is_not_compromise_activity():
    admin = dict(source_ip="10.20.1.52", source_ip_internal=True, source_in_baseline=True, failures_for_account=2,
                 post_privileged_actions=1, account_privileged=True)
    s = assess_severity(corr(**admin))
    assert s["severity"] == "low" and s["rule"].startswith("L2")
    assert any(f["effect"].startswith("neutral (expected") for f in s["factors"])
    # the same sudo from an unknown external source after brute force is still compromise activity
    s = assess_severity(corr(post_privileged_actions=1, account_privileged=True))
    assert s["severity"] == "critical"
