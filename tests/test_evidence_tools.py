"""Day 2 evidence tools and the wrapper's failure handling (offline, no Hermes, no LLM)."""
import json
import os
import shutil
import time
from pathlib import Path

import pytest

from soc_agent.config import ConfigError, parse_faults
from soc_agent.schemas import load_schema, problems
from soc_agent.tools.base import RunContext, ToolSpec, call_tool
from soc_agent.tools.evidence import (EVIDENCE_TOOLS, GET_ASSET_CONTEXT, LOOKUP_IP, SEARCH_CVE, SEARCH_LOGS,
                                      parse_version, resolve_ref)

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
ATTACKER = "203.0.113.77"


@pytest.fixture
def ctx():
    return RunContext("INV-TEST-EVIDENCE", {})


def run(spec, args, ctx):
    out, entry = call_tool(spec, args, ctx)
    return out, entry["status"], entry


def ok(spec, args, ctx):
    out, status, entry = run(spec, args, ctx)
    assert status == "ok", out
    assert problems(out, spec.output_schema) == []          # predictable output
    return out


# ------------------------------------------------------------- every tool: valid + output schema
@pytest.mark.parametrize("spec, args", [
    (SEARCH_LOGS, {"source": "all", "src_ip": ATTACKER}),
    (SEARCH_LOGS, {"source": "tshark", "dst_port": 22}),
    (LOOKUP_IP, {"ip": ATTACKER}),
    (SEARCH_CVE, {"product": "openssh", "version": "8.9p1"}),
    (GET_ASSET_CONTEXT, {"host": "fin-app-01"}),
    (GET_ASSET_CONTEXT, {"account": "j.mehta"}),
], ids=["search_logs-all", "search_logs-tshark", "lookup_ip", "search_cve", "asset-host", "asset-account"])
def test_valid_calls_match_their_output_schema(spec, args, ctx):
    out = ok(spec, args, ctx)
    assert out.get("data_label") in ("SYNTHETIC", "MOCK")


def test_every_tool_has_strict_input_and_an_output_schema():
    for spec in EVIDENCE_TOOLS:
        assert spec.permission == "read" and spec.output_schema is not None
        assert spec.parameters["additionalProperties"] is False
        assert spec.parameters == json.loads((ROOT / "schemas" / "tools" / f"{spec.name}.input.json").read_text())
    planned = set(load_schema("investigation_plan")["properties"]["steps"]["items"]["properties"]["tool"]["enum"])
    assert {s.name for s in EVIDENCE_TOOLS} == planned - {"analyst_review"}     # the plan names exactly these


def test_model_gets_simplified_schemas_but_the_wrapper_enforces_the_full_one(ctx):
    sent = json.dumps([s.hermes_schema() for s in EVIDENCE_TOOLS])
    for keyword in ('"pattern"', '"anyOf"', '"oneOf"', '"format"', '"errorMessage"'):
        assert keyword not in sent
    _, status, _ = run(SEARCH_LOGS, {"source": "wazuh"}, ctx)          # anyOf (dropped for the model) still applies
    assert status == "rejected"


# ------------------------------------------------------------------- schema rejections
@pytest.mark.parametrize("spec, args, needle", [
    (SEARCH_LOGS, {"source": "wazuh"}, "at least one filter besides source"),
    (SEARCH_LOGS, {"source": "wazuh", "event_type": "any"}, "at least one filter besides source"),
    (SEARCH_LOGS, {"account": "j.mehta"}, "'source' is a required property"),
    (SEARCH_LOGS, {"source": "splunk", "account": "j.mehta"}, "'splunk' is not one of"),
    (SEARCH_LOGS, {"source": "all", "src_ip": "203.0.113.300"}, "IPv4"),
    (SEARCH_LOGS, {"source": "all", "dst_ip": "fin-app-01"}, "IPv4"),
    (SEARCH_LOGS, {"source": "all", "account": "j.mehta", "start": "2026-11-18 09:00"}, "ISO 8601 UTC"),
    (SEARCH_LOGS, {"source": "all", "account": "j.mehta", "start": "2026-11-18T09:00:00+05:30"}, "ISO 8601 UTC"),
    (SEARCH_LOGS, {"source": "all", "account": "j.mehta", "start": "2026-02-30T09:00:00Z"}, "not a real date"),
    (SEARCH_LOGS, {"source": "all", "account": "j.mehta", "start": "2026-11-18T10:00:00Z",
                   "end": "2026-11-18T09:00:00Z"}, "is after end"),
    (SEARCH_LOGS, {"source": "all", "account": "j.mehta", "start": "2026-09-01T00:00:00Z",
                   "end": "2026-11-18T00:00:00Z"}, "maximum is 30 days"),
    (SEARCH_LOGS, {"source": "all", "account": "j.mehta", "query": "*"}, "'query' was unexpected"),
    (SEARCH_LOGS, {"source": "all", "account": "j.mehta", "limit": 0}, "less than the minimum of 1"),
    (SEARCH_LOGS, {"source": "all", "account": "j.mehta", "limit": 201}, "greater than the maximum of 200"),
    (SEARCH_LOGS, {"source": "all", "account": "j.mehta", "event_type": "authentication"}, "is not one of"),
    (SEARCH_LOGS, {"source": "all", "dst_port": 70000}, "65535"),
    (LOOKUP_IP, {"ip": "999.1.1.1"}, "IPv4"),
    (LOOKUP_IP, {"ip": "2001:db8::1"}, "IPv4"),
    (LOOKUP_IP, {"ip": "203.0.113.077"}, "IPv4"),
    (LOOKUP_IP, {}, "'ip' is a required property"),
    (LOOKUP_IP, {"ip": ATTACKER, "live": True}, "'live' was unexpected"),
    (LOOKUP_IP, {"ip": "224.0.0.1"}, "not a unicast host address"),
    (LOOKUP_IP, {"ip": "0.0.0.0"}, "not a unicast host address"),
    (SEARCH_CVE, {}, "'product' is a required property"),
    (SEARCH_CVE, {"product": "openssh; rm -rf /"}, "product name"),
    (SEARCH_CVE, {"product": "openssh", "version": "latest"}, "a version such as"),
    (SEARCH_CVE, {"product": "openssh", "version": "8.x"}, "is not a version like"),
    (GET_ASSET_CONTEXT, {}, "exactly one of host or account"),
    (GET_ASSET_CONTEXT, {"host": "fin-app-01", "account": "j.mehta"}, "exactly one of host or account"),
    (GET_ASSET_CONTEXT, {"host": "fin-app-01", "owner": "x"}, "'owner' was unexpected"),
])
def test_bad_input_is_rejected_with_a_readable_problem(spec, args, needle, ctx):
    out, status, entry = run(spec, args, ctx)
    assert status == "rejected" and "error" in out
    assert needle in json.dumps(out), out
    assert entry["evidence_refs"] == [] and ctx.evidence_refs == {}            # nothing returned, nothing citable


def test_non_object_arguments_are_rejected(ctx):
    out, status, _ = run(SEARCH_LOGS, ["wazuh"], ctx)
    assert status == "rejected" and "JSON object" in out["error"]


# --------------------------------------------------------------------------- zero results
@pytest.mark.parametrize("spec, args, check", [
    (SEARCH_LOGS, {"source": "all", "account": "nobody"}, lambda r: r["events"] == [] and r["total_matched"] == 0),
    (SEARCH_LOGS, {"source": "wazuh", "event_type": "network_session"}, lambda r: r["total_matched"] == 0),
    (SEARCH_LOGS, {"source": "all", "account": "j.mehta", "start": "2026-11-19T00:00:00Z"},
     lambda r: r["total_matched"] == 0 and r["first_time"] is None),
    (SEARCH_CVE, {"product": "openssh", "version": "9.8p1"}, lambda r: r["matches"] == [] and r["total"] == 0),
    (SEARCH_CVE, {"product": "postgresql", "version": "14.13"}, lambda r: r["matches"] == [] and r["product_matched"] is None),
    (LOOKUP_IP, {"ip": "192.0.2.200"}, lambda r: r["found"] is False and r["classification"] == "unknown"),
    (GET_ASSET_CONTEXT, {"host": "mail-01"}, lambda r: r["found"] is False and "record" not in r),
    (GET_ASSET_CONTEXT, {"account": "ghost"}, lambda r: r["found"] is False),
])
def test_zero_results_are_ok_not_errors(spec, args, check, ctx):
    out = ok(spec, args, ctx)
    assert check(out)
    assert ctx.tool_calls[-1]["evidence_refs"] == []
    assert "evidence_ref" not in json.dumps(out)


def test_search_logs_explains_an_empty_result(ctx):
    out = ok(SEARCH_LOGS, {"source": "all", "account": "nobody"}, ctx)
    assert "valid result" in out["notes"][0] and out["truncated"] is False


# ----------------------------------------------------------------------------- search_logs
def test_malformed_lines_are_skipped_and_counted(ctx):
    out = ok(SEARCH_LOGS, {"source": "wazuh", "host": "fin-app-01"}, ctx)
    assert out["malformed_lines_skipped"] == 2
    assert ok(SEARCH_LOGS, {"source": "tshark", "host": "fin-app-01"}, ctx)["malformed_lines_skipped"] == 0
    assert ok(SEARCH_LOGS, {"source": "all", "host": "fin-app-01"}, ctx)["malformed_lines_skipped"] == 2


def test_evidence_refs_are_stable_and_point_at_the_right_line(ctx):
    args = {"source": "all", "src_ip": ATTACKER, "limit": 200}
    first, again = ok(SEARCH_LOGS, args, ctx), ok(SEARCH_LOGS, args, ctx)
    assert [e["evidence_ref"] for e in first["events"]] == [e["evidence_ref"] for e in again["events"]]
    assert len({e["evidence_ref"] for e in first["events"]}) == first["returned"]     # one ref per record
    for ev in first["events"]:
        raw = resolve_ref(ev["evidence_ref"])
        if ev["source"] == "wazuh":
            line = json.loads(raw)
            assert line["data"]["srcip"] == ATTACKER and line["timestamp"][:19] == ev["time"][:19]
            assert line["full_log"] in ev["summary"]
        else:
            assert raw["ip.src"] == ATTACKER and raw["tcp.dstport"] == "22"
            assert f"tcp.stream {raw['tcp.stream']})" in ev["summary"]


def test_wazuh_line_numbers_match_the_file(ctx):
    out = ok(SEARCH_LOGS, {"source": "wazuh", "event_type": "account_change"}, ctx)
    (ev,) = out["events"]
    n = int(ev["evidence_ref"].split("#L")[1])
    line = (DATA / "logs" / "wazuh_alerts.jsonl").read_text().splitlines()[n - 1]
    assert "backup_svc" in line and ev["account"] == "backup_svc" and ev["time"] == "2026-11-18T09:46:11.007Z"


def test_spraying_signal_is_found_by_source_ip(ctx):
    out = ok(SEARCH_LOGS, {"source": "wazuh", "src_ip": ATTACKER, "event_type": "auth_failure", "limit": 200}, ctx)
    by_account = {}
    for e in out["events"]:
        by_account[e["account"]] = by_account.get(e["account"], 0) + 1
    assert by_account == {"j.mehta": 50, "a.rao": 3}
    rao = [e for e in out["events"] if e["account"] == "a.rao"]
    assert all(e["time"] < "2026-11-18T09:31:02" for e in rao)                 # before the j.mehta burst


def test_the_alerted_scenario_is_in_the_logs(ctx):
    out = ok(SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta", "host": "fin-app-01",
                           "start": "2026-11-18T09:31:02Z", "end": "2026-11-18T09:42:17Z", "limit": 200}, ctx)
    assert out["counts"]["by_event_type"] == {"auth_failure": 50, "auth_success": 1}   # end covers 09:42:17.512
    assert out["first_time"] == "2026-11-18T09:31:02.000Z" and out["last_time"] == "2026-11-18T09:42:17.512Z"
    assert out["events"][-1]["src_ip"] == ATTACKER and "Accepted password" in out["events"][-1]["summary"]
    normal = ok(SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta", "src_ip": "10.20.1.45"}, ctx)
    assert [e["time"][:10] for e in normal["events"]] == ["2026-11-16", "2026-11-17"]


def test_tshark_sessions_are_counted_correctly(ctx):
    out = ok(SEARCH_LOGS, {"source": "tshark", "src_ip": ATTACKER, "dst_port": 22, "limit": 200}, ctx)
    assert out["total_matched"] == 54 and out["counts"]["by_source"] == {"tshark": 54}
    long_ = [e for e in out["events"] if float(e["summary"].split("duration ")[1].split(" s")[0]) > 60]
    assert len(long_) == 1 and long_[0]["time"].startswith("2026-11-18T09:42:15")
    assert all(e["host"] == "fin-app-01" and e["account"] is None for e in out["events"])
    assert any("SSH is encrypted" in n for n in out["notes"])
    outbound = ok(SEARCH_LOGS, {"source": "tshark", "dst_ip": "198.51.100.23"}, ctx)
    (ev,) = outbound["events"]
    assert ev["src_ip"] == "10.20.5.17" and ev["dst_port"] == 443 and ev["host"] == "fin-app-01"


def test_results_are_sorted_truncated_and_counted_over_all_matches(ctx):
    out = ok(SEARCH_LOGS, {"source": "all", "src_ip": ATTACKER, "limit": 10}, ctx)
    assert out["returned"] == 10 and out["total_matched"] == 108 and out["truncated"] is True
    assert sum(out["counts"]["by_source"].values()) == 108
    times = [e["time"] for e in out["events"]]
    assert times == sorted(times) and out["first_time"] == times[0]
    assert any("Only the earliest 10 of 108" in n for n in out["notes"])
    assert len(ctx.tool_calls[-1]["evidence_refs"]) == 10          # only returned records are citable


def test_host_filter_accepts_a_name_or_an_ip_case_insensitively(ctx):
    by_name = ok(SEARCH_LOGS, {"source": "all", "host": "FIN-APP-01"}, ctx)
    by_ip = ok(SEARCH_LOGS, {"source": "all", "host": "10.20.5.17"}, ctx)
    assert by_name["total_matched"] == by_ip["total_matched"] > 100


# ------------------------------------------------------------------------------- lookup_ip
@pytest.mark.parametrize("ip, classification, found", [
    (ATTACKER, "malicious", True), ("198.51.100.23", "suspicious", True), ("10.20.1.45", "internal", False),
    ("192.168.1.10", "internal", False), ("172.20.0.5", "internal", False), ("8.8.8.8", "unknown", False),
])
def test_lookup_ip_classifications_are_always_mock_and_offline(ip, classification, found, ctx):
    out = ok(LOOKUP_IP, {"ip": ip}, ctx)
    assert out["classification"] == classification and out["found"] is found
    assert out["source"] == "MOCK intel feed" and out["live"] is False and out["data_label"] == "MOCK"
    assert ("evidence_ref" in out) is found


def test_malicious_ip_details(ctx):
    out = ok(LOOKUP_IP, {"ip": ATTACKER}, ctx)
    assert out["reputation_score"] == 92 and "ssh-bruteforce" in out["categories"]
    assert out["evidence_ref"] == f"ip_reputation.json#{ATTACKER}" and resolve_ref(out["evidence_ref"])["asn"] == 64500


def test_documentation_ranges_are_not_treated_as_internal(ctx):
    import ipaddress
    assert ipaddress.ip_address(ATTACKER).is_private          # Python's view: why is_private is not used
    assert ok(LOOKUP_IP, {"ip": ATTACKER}, ctx)["classification"] == "malicious"


def test_internal_ips_are_never_sent_to_the_feed(tmp_path):
    ctx = RunContext("INV-TEST-NOFEED", {}, data_dir=tmp_path)          # no feed file at all
    out, status, _ = run(LOOKUP_IP, {"ip": "10.20.1.45"}, ctx)
    assert status == "ok" and out["classification"] == "internal"
    out, status, _ = run(LOOKUP_IP, {"ip": ATTACKER}, ctx)
    assert status == "error" and "ip_reputation.json is unavailable" in out["error"]


# ------------------------------------------------------------------------------ search_cve
@pytest.mark.parametrize("version, expected", [
    ("8.9p1", {"CVE-2024-6387", "CVE-2023-38408", "CVE-2023-48795", "CVE-2023-51385"}),
    ("8.7p1", {"CVE-2024-6387", "CVE-2023-38408", "CVE-2023-48795", "CVE-2023-51385", "CVE-2021-41617"}),
    ("8.4p1", {"CVE-2023-38408", "CVE-2023-48795", "CVE-2023-51385", "CVE-2021-41617"}),    # before 6387's range
    ("4.3p2", {"CVE-2024-6387", "CVE-2023-38408", "CVE-2023-48795", "CVE-2023-51385"}),     # 6387's old range
    ("9.3p1", {"CVE-2024-6387", "CVE-2023-38408", "CVE-2023-48795", "CVE-2023-51385"}),
    ("9.3p2", {"CVE-2024-6387", "CVE-2023-48795", "CVE-2023-51385"}),                         # fixed is exclusive
    ("9.6p1", {"CVE-2024-6387"}),
    ("9.8p1", set()),
    ("1:8.9p1-3ubuntu0.6", {"CVE-2024-6387", "CVE-2023-38408", "CVE-2023-48795", "CVE-2023-51385"}),
])
def test_cve_matching_is_version_range_aware(version, expected, ctx):
    out = ok(SEARCH_CVE, {"product": "openssh", "version": version}, ctx)
    assert {m["cve_id"] for m in out["matches"]} == expected and out["total"] == len(expected)
    assert out["version_checked"] is True and out["source"] == "MOCK CVE database" and out["live"] is False


def test_cve_aliases_package_versions_and_no_version(ctx):
    out = ok(SEARCH_CVE, {"product": "SSHD", "version": "1:8.9p1-3ubuntu0.6"}, ctx)
    assert out["product_matched"] == "openssh" and out["version_compared"] == "8.9p1"
    assert any("backports" in n for n in out["notes"])
    every = ok(SEARCH_CVE, {"product": "openssh"}, ctx)
    assert every["total"] == 5 and every["version_checked"] is False
    assert any("which ones apply is unknown" in n for n in every["notes"])
    assert all(resolve_ref(m["evidence_ref"])["cve_id"] == m["cve_id"] for m in every["matches"])


@pytest.mark.parametrize("text, expected", [("8.9p1", (8, 9, 0, 1)), ("9.6", (9, 6, 0, 0)), ("0", (0, 0, 0, 0)),
                                            ("1:8.9p1-3ubuntu0.6", (8, 9, 0, 1)), ("10.0.2p3", (10, 0, 2, 3))])
def test_parse_version(text, expected):
    assert parse_version(text)[1] == expected


# ----------------------------------------------------------------------- get_asset_context
def test_asset_context_for_hosts_and_accounts(ctx):
    host = ok(GET_ASSET_CONTEXT, {"host": "fin-app-01"}, ctx)
    rec = host["record"]
    assert rec["criticality"] == "high" and rec["internet_exposed"] is True
    assert {"name": "sshd", "product": "openssh", "version": "8.9p1", "port": 22}.items() <= rec["services"][0].items()
    assert host["evidence_ref"] == "inventory.json#hosts/fin-app-01"
    assert ok(GET_ASSET_CONTEXT, {"host": "10.20.5.30"}, ctx)["record"]["name"] == "db-fin-01"
    acct = ok(GET_ASSET_CONTEXT, {"account": "J.Mehta"}, ctx)["record"]
    assert acct["privileged"] is False and acct["usual_source_ips"] == ["10.20.1.45"]


# ------------------------------------------------------------------------- data files
def test_data_files_are_labelled_synthetic_or_mock():
    for rel in ("intel/ip_reputation.json", "intel/cve_db.json", "assets/inventory.json"):
        assert json.loads((DATA / rel).read_text())["_synthetic"] is True
    assert "SYNTHETIC" in (DATA / "logs" / "wazuh_alerts.jsonl").read_text().splitlines()[0]
    assert "SYNTHETIC" in (DATA / "logs" / "tshark_sessions.csv").read_text().splitlines()[0]
    assert "MOCK" in (DATA / "intel" / "ip_reputation.json").read_text()[:200]


def test_log_generator_is_deterministic(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("mk", ROOT / "scripts" / "make_synthetic_logs.py")
    mk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mk)
    monkeypatch.setattr(mk, "LOGS", tmp_path)
    monkeypatch.setattr(mk, "SCENARIO_BASE", tmp_path / "scenarios")      # never rewrite the repo in a test
    mk.main()
    for name in ("wazuh_alerts.jsonl", "tshark_sessions.csv"):
        assert (tmp_path / name).read_bytes() == (DATA / "logs" / name).read_bytes()
    made = sorted(p.relative_to(tmp_path / "scenarios") for p in (tmp_path / "scenarios").rglob("*") if p.is_file())
    assert made == sorted(p.relative_to(DATA / "scenarios") for p in (DATA / "scenarios").rglob("*")
                          if p.is_file() and p.name != "README.md")
    for rel in made:                                                       # Day 3 scenario roots too
        assert (tmp_path / "scenarios" / rel).read_bytes() == (DATA / "scenarios" / rel).read_bytes(), rel


def test_tools_make_no_network_calls():
    src = (ROOT / "src" / "soc_agent" / "tools" / "evidence.py").read_text()
    for mod in ("socket", "urllib", "requests", "httpx", "http.client", "subprocess"):
        assert f"import {mod}" not in src and f"from {mod}" not in src


# ----------------------------------------------------------- wrapper: failures are safe and visible
def test_injected_timeout_returns_no_data(ctx):
    ctx.faults, ctx.tool_timeout_s = {"lookup_ip": "timeout"}, 0.2
    t0 = time.perf_counter()
    out, status, entry = run(LOOKUP_IP, {"ip": ATTACKER}, ctx)
    assert status == "timeout" and out == {"error": out["error"], "retryable": True}
    assert "timed out after 0.2 s" in out["error"] and "do not guess" in out["error"]
    assert time.perf_counter() - t0 < 2 and entry["fault_injected"] == "timeout" and entry["timeout_s"] == 0.2
    assert ctx.evidence_refs == {}


def test_a_slow_real_handler_times_out(ctx):
    slow = ToolSpec("slow", "sleeps", {"type": "object", "properties": {}, "additionalProperties": False},
                    handler=lambda a, c: time.sleep(0.6) or {"late": True}, timeout_s=0.1)
    out, status, _ = run(slow, {}, ctx)
    assert status == "timeout" and "late" not in out


def test_handler_raising_timeouterror_is_an_error_not_a_timeout(ctx):
    def boom(a, c):
        raise TimeoutError("upstream said so")
    spec = ToolSpec("boom", "x", {"type": "object", "properties": {}, "additionalProperties": False}, handler=boom)
    out, status, _ = run(spec, {}, ctx)
    assert status == "error" and "upstream said so" in out["error"]


@pytest.mark.parametrize("kind, needle", [("error", "[FAULT INJECTION] search_cve: simulated data source failure"),
                                          ("malformed", "does not match its output schema")])
def test_injected_errors_and_malformed_output(kind, needle, ctx):
    ctx.faults = {"search_cve": kind}
    out, status, entry = run(SEARCH_CVE, {"product": "openssh"}, ctx)
    assert status == "error" and needle in out["error"] and entry["fault_injected"] == kind
    assert "matches" not in out                                   # never any data


def test_fault_injection_comes_after_input_validation(ctx):
    ctx.faults = {"lookup_ip": "timeout"}
    _, status, entry = run(LOOKUP_IP, {"ip": "nope"}, ctx)
    assert status == "rejected" and entry["fault_injected"] is None


def test_malformed_handler_output_is_withheld(ctx):
    bad = ToolSpec("lookup_ip", "x", LOOKUP_IP.parameters, handler=lambda a, c: {"ip": a["ip"], "verdict": "evil"},
                   output_schema=LOOKUP_IP.output_schema)
    out, status, entry = run(bad, {"ip": ATTACKER}, ctx)
    assert status == "error" and "evil" not in json.dumps(out) and out["retryable"] is False   # value withheld
    assert any("'verdict' was unexpected" in p for p in out["problems"])
    notdict = ToolSpec("x", "x", {"type": "object"}, handler=lambda a, c: ["a", "list"])
    out, status, _ = run(notdict, {}, ctx)
    assert status == "error" and "not a JSON object" in out["error"]


def test_missing_data_file_is_a_clear_error_not_a_crash(tmp_path):
    ctx = RunContext("INV-TEST-MISSING", {}, data_dir=tmp_path)
    for spec, args, name in [(SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta"}, "wazuh_alerts.jsonl"),
                             (SEARCH_LOGS, {"source": "tshark", "dst_port": 22}, "tshark_sessions.csv"),
                             (SEARCH_CVE, {"product": "openssh"}, "cve_db.json"),
                             (GET_ASSET_CONTEXT, {"host": "fin-app-01"}, "inventory.json")]:
        out, status, _ = run(spec, args, ctx)
        assert status == "error" and out["error"] == f"Data source {name} is unavailable (file not found)."
        assert str(tmp_path) not in json.dumps(out) and os.path.expanduser("~") not in json.dumps(out)


@pytest.mark.parametrize("rel, content, needle", [
    ("intel/cve_db.json", "{not json", "cve_db.json is corrupt (not valid JSON"),
    ("intel/cve_db.json", "[1, 2]", "cve_db.json is corrupt (expected a JSON object)"),
    ("intel/ip_reputation.json", '{"records": []}', "ip_reputation.json is corrupt (missing 'records'"),
    ("logs/tshark_sessions.csv", "a,b,c\n1,2,3\n", "tshark_sessions.csv is corrupt (expected the columns"),
])
def test_corrupt_data_file_is_a_clear_error(tmp_path, rel, content, needle):
    shutil.copytree(DATA, tmp_path / "data")
    (tmp_path / "data" / rel).write_text(content)
    ctx = RunContext("INV-TEST-CORRUPT", {}, data_dir=tmp_path / "data")
    spec, args = {"intel/cve_db.json": (SEARCH_CVE, {"product": "openssh"}),
                  "intel/ip_reputation.json": (LOOKUP_IP, {"ip": ATTACKER}),
                  "logs/tshark_sessions.csv": (SEARCH_LOGS, {"source": "tshark", "dst_port": 22})}[rel]
    out, status, _ = run(spec, args, ctx)
    assert status == "error" and needle in out["error"]


def test_audit_entries_are_capped_but_keep_the_refs(ctx):
    ctx.audit_result_max_chars = 500
    out, status, entry = run(SEARCH_LOGS, {"source": "all", "src_ip": ATTACKER, "limit": 200}, ctx)
    assert status == "ok" and len(out["events"]) == 108                     # the model got everything
    stored = entry["result"]
    assert entry["result_truncated"] is True and stored["_truncated"] is True
    assert stored["original_chars"] > 500 and len(stored["preview"]) == 500
    assert len(entry["evidence_refs"]) == 108 and entry["result_summary"].startswith("108 matched")
    small, _, e2 = run(LOOKUP_IP, {"ip": ATTACKER}, ctx)
    assert e2["result"] == small and e2["result_truncated"] is False


def test_refs_are_only_recorded_for_successful_read_calls(ctx):
    ok(LOOKUP_IP, {"ip": ATTACKER}, ctx)
    run(LOOKUP_IP, {"ip": "bad"}, ctx)
    assert ctx.evidence_refs == {f"ip_reputation.json#{ATTACKER}": "lookup_ip"}


def test_phase_allowlist_denies_other_tools(ctx):
    ctx.allowed_tools = frozenset({"get_alert", "submit_investigation_plan"})
    out, status, _ = run(SEARCH_LOGS, {"source": "all", "src_ip": ATTACKER}, ctx)
    assert status == "denied" and "not available in this phase" in out["error"]


def test_soc_faults_parsing():
    assert parse_faults("lookup_ip:timeout, search_cve:error") == {"lookup_ip": "timeout", "search_cve": "error"}
    assert parse_faults("") == {}
    for bad in ("lookup_ip", "lookup_ip:explode", ":timeout"):
        with pytest.raises(ConfigError, match="Bad fault"):
            parse_faults(bad)


def test_settings_read_faults_and_timeout_from_env(monkeypatch):
    from soc_agent.config import load_settings
    monkeypatch.setenv("SOC_FAULTS", "lookup_ip:timeout")
    monkeypatch.setenv("SOC_TOOL_TIMEOUT_S", "0.5")
    s = load_settings("mock")
    assert s.faults == {"lookup_ip": "timeout"} and s.tool_timeout_s == 0.5
    monkeypatch.setenv("SOC_TOOL_TIMEOUT_S", "soon")
    with pytest.raises(ConfigError, match="SOC_TOOL_TIMEOUT_S"):
        load_settings("mock")


def test_resolve_ref_rejects_unknown_refs():
    for ref in ("wazuh_alerts.jsonl#L999", "tshark_sessions.csv#row0", "nope.json#x", "inventory.json#hosts/ghost",
                "../../etc/passwd#L1", "cve_db.json#CVE-1999-0001"):
        assert resolve_ref(ref) is None
