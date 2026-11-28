"""Day 4 incident report: schema, Markdown, evidence refs vs the audit trail, approval status, versions,
and the checks of submit_report_content (the agent's only contribution)."""
import copy
import json
from pathlib import Path

import pytest

from soc_agent.approvals import approve, execute, reject
from soc_agent.report import (MOCK_LLM_BANNER, SYNTHETIC_BANNER, build_report, refresh_report, render_markdown,
                              report_problems, save_report)
from soc_agent.schemas import load_schema, problems
from soc_agent.store import UNDER_INVESTIGATION, Store
from soc_agent.tools.base import RunContext, call_tool, collect_refs
from soc_agent.tools.reporting import SUBMIT_REPORT_CONTENT

SECTIONS = ("## Summary", "## Executive summary", "## Severity and confidence", "## Affected entities",
            "## Timeline", "## Assessment", "## MITRE ATT&CK", "## Recommendations",
            "## Actions requested by the agent (approval workflow)", "## Gaps and unknowns",
            "## Alternative explanations", "## Evidence appendix", "## Provenance")


def test_report_json_validates_against_the_schema(report_run):
    r = report_run.report
    assert r.status == "completed" and r.report_version == 1
    rep = json.loads(Path(r.report_json_path).read_text())
    assert problems(rep, load_schema("incident_report")) == []
    stored = report_run.store.report(report_run.investigation_id)
    assert stored["version"] == 1 and stored["json"]["incident_id"] == report_run.investigation_id
    assert stored["markdown"] == Path(r.report_md_path).read_text()


def test_report_fields_come_from_the_stored_assessment(report_run):
    rep = report_run.store.report(report_run.investigation_id)["json"]
    f = report_run.assessment.assessment["findings"]
    assert (rep["severity"], rep["confidence"]) == (f["severity"], f["confidence"]) == ("critical", "high")
    assert rep["severity_rationale"] == f["severity_rationale"] and rep["mitre"] == f["mitre"]
    assert rep["confidence_rationale"] == f["confidence_rationale"]
    assert rep["gaps_unknowns"]["unknowns"] == f["unknowns"]
    assert rep["rubric_agreement"]["agrees"] is True and rep["status"] == "Awaiting Approval"
    assert rep["executive_summary"]["source"] == "agent" and len(rep["executive_summary"]["text"].split()) <= 150
    assert {k: rep["provenance"][k] for k in ("runtime", "provider", "mock")} == {
        "runtime": "hermes-agent", "provider": "mock", "mock": True}
    assert rep["data_labels"]["synthetic_data"] is True and "MOCK" in rep["data_labels"]["intel"]
    ents = rep["affected_entities"]
    assert {"j.mehta", "backup_svc"} <= {a["name"] for a in ents["accounts"]}
    ips = {i["ip"]: i for i in ents["ips"]}
    assert ips["203.0.113.77"]["internal"] is False and "MOCK intel" in ips["203.0.113.77"]["reputation"]
    assert "outbound destination after the login" in ips["198.51.100.23"]["roles"]
    assert rep["timeline"][0]["phase"] == "baseline" and any(t["phase"] == "compromise" for t in rep["timeline"])


def test_markdown_has_every_section_and_the_labels(report_run):
    md = Path(report_run.report.report_md_path).read_text()
    for s in SECTIONS:
        assert s in md, s
    assert md.index(SYNTHETIC_BANNER) < md.index("## Summary") and MOCK_LLM_BANNER in md
    assert "| time (UTC) | phase | event | count | evidence |" in md
    assert "SIMULATED" in md and "PENDING" in md
    assert "`wazuh_alerts.jsonl#L64`" in md


def test_every_report_ref_exists_in_the_audit_trail(report_run):
    st, inv = report_run.store, report_run.investigation_id
    rep = st.report(inv)["json"]
    refs = set(collect_refs(rep)) | set(rep["severity_evidence_refs"]) | set(rep["executive_summary"]["evidence_refs"])
    audited = {r for c in st.tool_calls(inv) if c["status"] == "ok" for r in c["evidence_refs"]}
    assert refs and refs <= audited and refs <= set(st.evidence(inv))
    assert {e["ref"] for e in rep["evidence_appendix"]} == refs
    assert all(e["excerpt"] and e["excerpt"] != "(not in the evidence index)" for e in rep["evidence_appendix"])


def test_containment_recommendations_require_approval_and_link_their_action(report_run):
    rep = report_run.store.report(report_run.investigation_id)["json"]
    actions = {a["id"]: a for a in report_run.store.actions(report_run.investigation_id)}
    contain = [r for r in rep["recommendations"] if r["type"] == "containment"]
    assert len(contain) == 4 and [r["priority"] for r in rep["recommendations"]] == sorted(
        r["priority"] for r in rep["recommendations"])
    for r in contain:
        assert r["requires_approval"] is True and r["pending_action_id"] in actions
        assert r["approval_status"] == "pending" and r["linked_by"] == "agent"
    for r in rep["recommendations"]:
        if r["type"] == "remediation":
            assert r["requires_approval"] is True and r["approval_status"] == "analyst_decision_required"
        if r["type"] == "investigative":
            assert r["approval_status"] == "not_required"
    assert {p["action_id"] for p in rep["pending_actions"]} == set(actions)


def test_schema_refuses_containment_without_approval(report_run):
    rep = copy.deepcopy(report_run.store.report(report_run.investigation_id)["json"])
    rec = next(r for r in rep["recommendations"] if r["type"] == "containment")
    rec["requires_approval"], rec["approval_status"] = False, "not_required"
    assert any("requires_approval" in p or "True was expected" in p for p in report_problems(rep))


def test_markdown_escapes_log_text(report_run):
    rep = copy.deepcopy(report_run.store.report(report_run.investigation_id)["json"])
    rep["evidence_appendix"].append({"ref": "wazuh_alerts.jsonl#L68", "tool": "search_logs",
                                     "excerpt": "a | b <script>x</script> `c`\n## fake heading"})
    md = render_markdown(rep)
    line = next(ln for ln in md.splitlines() if "fake heading" in ln)
    # log text stays inside one table row, as a code span (literal text in Markdown): no new heading, no HTML
    assert line.startswith("| `wazuh_alerts.jsonl#L68` |") and "`a \\| b <script>x</script> 'c' ## fake heading`" in line
    assert "\n## fake heading" not in md
    rep["title"] = "<img src=x onerror=alert(1)>"
    assert "<img" not in render_markdown(rep)                # text outside code spans is HTML-escaped


def test_new_report_versions_track_the_approval_workflow(tmp_path, report_run):
    # copy the database so the module's run stays untouched
    db = tmp_path / "copy.db"
    db.write_bytes(Path(report_run.settings.db_path).read_bytes())
    st, inv = Store(db), report_run.investigation_id
    assert refresh_report(st, inv, tmp_path / "reports") is None          # nothing changed yet
    acts = st.actions(inv)
    approve(st, acts[0]["id"], "Priya", "block the source")
    v2 = refresh_report(st, inv, tmp_path / "reports")
    rec = next(r for r in v2["report"]["recommendations"] if r["pending_action_id"] == acts[0]["id"])
    assert v2["version"] == 2 and rec["approval_status"] == "approved"
    execute(st, acts[0]["id"], tmp_path / "sim.log", analyst="Priya")
    for a in acts[1:]:
        reject(st, a["id"], "Priya", "not needed yet")
    v3 = refresh_report(st, inv, tmp_path / "reports")
    pa = {p["action_id"]: p for p in v3["report"]["pending_actions"]}
    assert pa[acts[0]["id"]]["status"] == "executed" and pa[acts[0]["id"]]["simulated_execution"]["executed_by"] == "Priya"
    assert pa[acts[1]["id"]]["decision"]["decision"] == "rejected"
    assert v3["report"]["status"] == UNDER_INVESTIGATION and "**executed**" in v3["markdown"]
    assert [v["version"] for v in st.report_versions(inv)] == [1, 2, 3]
    with pytest.raises(Exception, match="append-only"):
        with st.tx() as conn:
            conn.execute("UPDATE reports SET markdown = 'x'")


def test_report_without_agent_content(mock_settings, alert):
    """If the report phase never produced accepted content, the report is still assembled from the assessment,
    with no executive summary and no agent recommendations (nothing is filled in for the agent)."""
    from soc_agent.assessor import analyze_alert

    plan, res = analyze_alert(alert, mock_settings)
    st = Store(mock_settings.db_path)
    rep = build_report(st, plan.investigation_id)
    assert report_problems(rep) == []
    assert rep["executive_summary"] == {"text": None, "evidence_refs": [], "source": "none"}
    assert rep["recommendations"] == [] and rep["recommendations_source"].startswith("none")
    md = render_markdown(rep)
    assert "No executive summary" in md and "Assessment next steps" in md
    saved = save_report(st, rep, mock_settings.reports_dir)
    assert saved["version"] == 1 and Path(saved["md_path"]).is_file()


# ------------------------------------------------------------------ submit_report_content checks
@pytest.fixture
def rctx(report_run, tmp_path):
    db = tmp_path / "copy.db"
    db.write_bytes(Path(report_run.settings.db_path).read_bytes())
    st, inv = Store(db), report_run.investigation_id
    ctx = RunContext(investigation_id=inv, alert=st.investigation(inv)["alert"], store=st, phase="report")
    ctx.evidence_index = st.evidence(inv)
    ctx.evidence_refs = {r: e["tool"] for r, e in ctx.evidence_index.items()}
    return ctx


def content(**kw):
    base = {"executive_summary": "An external address guessed the password of j.mehta and logged in; sudo and a "
                                 "new account followed. Severity critical, confidence high.",
            "summary_evidence_refs": ["wazuh_alerts.jsonl#L64"],
            "recommendations": [{"priority": 1, "action": "Confirm with j.mehta whether the logins were theirs.",
                                 "type": "investigative", "rationale": "Separates misuse from user error.",
                                 "expected_impact": "None.", "evidence_refs": ["wazuh_alerts.jsonl#L64"],
                                 "requires_approval": False}]}
    return base | kw


def test_valid_report_content_accepted(rctx):
    out, entry = call_tool(SUBMIT_REPORT_CONTENT, content(), rctx)
    assert entry["status"] == "ok" and out["accepted"] is True and rctx.report_content is not None


@pytest.mark.parametrize("change, expect", [
    ({"executive_summary": "word " * 151}, "151 words"),
    ({"summary_evidence_refs": ["wazuh_alerts.jsonl#L999"]}, "was not returned"),
    ({"executive_summary": "203.0.113.77 is a known malicious scanner per threat intel and it logged in."},
     "ip_reputation.json#203.0.113.77"),
])
def test_bad_summary_rejected(rctx, change, expect):
    out, entry = call_tool(SUBMIT_REPORT_CONTENT, content(**change), rctx)
    assert entry["status"] == "rejected" and expect in json.dumps(out), out


def _rec(**kw):
    return {"priority": 1, "action": "Block 203.0.113.77 at the perimeter.", "type": "containment",
            "rationale": "Brute-force source.", "expected_impact": "No traffic from it.",
            "evidence_refs": ["wazuh_alerts.jsonl#L64"], "requires_approval": True} | kw


@pytest.mark.parametrize("recs, expect", [
    ([_rec(requires_approval=False)], "needs requires_approval: true"),
    ([_rec(type="remediation", requires_approval=False)], "needs requires_approval: true"),
    ([_rec(type="investigative", requires_approval=False)], "is a containment action"),
    ([_rec(), _rec(action="Isolate fin-app-01.")], "used more than once"),
    ([_rec(pending_action_id="ACT-0000000000")], "is not an action requested"),
    ([_rec(evidence_refs=["tshark_sessions.csv#row999"])], "was not returned"),
    ([_rec(approved=True)], "Additional properties"),
])
def test_bad_recommendations_rejected(rctx, recs, expect):
    out, entry = call_tool(SUBMIT_REPORT_CONTENT, content(recommendations=recs), rctx)
    assert entry["status"] == "rejected" and expect in json.dumps(out), out
    assert rctx.report_content is None


def test_report_content_must_cite_actions_requested_in_the_run(rctx):
    from soc_agent.tools.actions import REQUEST_ACTION

    rctx.store.set_status(rctx.investigation_id, UNDER_INVESTIGATION, "system", "x", if_from={"Awaiting Approval"})
    for a in rctx.store.actions(rctx.investigation_id):           # decide the earlier ones (other run)
        reject(rctx.store, a["id"], "Priya", "superseded by this test")
    out, entry = call_tool(REQUEST_ACTION, {"action_type": "block_ip", "target": "203.0.113.77",
                                            "reason": "Brute-force source.", "evidence_refs": ["wazuh_alerts.jsonl#L64"],
                                            "expected_impact": "Blocks the source."}, rctx)
    assert entry["status"] == "ok", out
    rej, e2 = call_tool(SUBMIT_REPORT_CONTENT, content(), rctx)
    assert e2["status"] == "rejected" and out["action_id"] in json.dumps(rej)
    ok, e3 = call_tool(SUBMIT_REPORT_CONTENT, content(recommendations=[
        _rec(pending_action_id=out["action_id"])]), rctx)
    assert e3["status"] == "ok", ok


@pytest.mark.parametrize("name, n_actions", [("compromise", 4), ("benign", 0), ("failures_only", 1),
                                             ("incomplete", 3), ("tool_failure", 4), ("conflicting", 2)])
def test_report_phase_on_every_scenario(name, n_actions, mock_settings):
    """run (plan -> assess -> report) on each SYNTHETIC scenario: a schema-valid report, only pending requests,
    and the right status (no requests -> stays Under Investigation)."""
    from soc_agent.reporter import run_alert
    from soc_agent.scenarios import load_scenario

    sc = load_scenario(name)
    plan, res, rep = run_alert(sc.alert, sc.settings(mock_settings), faults=sc.manifest["faults"])
    assert rep is not None and rep.status == "completed", (rep and rep.error)
    st = Store(mock_settings.db_path)
    report = st.report(plan.investigation_id)["json"]
    assert report_problems(report) == []
    assert len(rep.pending_actions) == n_actions and {a["status"] for a in rep.pending_actions} <= {"pending"}
    assert report["status"] == ("Awaiting Approval" if n_actions else "Under Investigation")
    assert st.simulated(plan.investigation_id) == [] and st.verify_audit()["ok"]


def test_agent_summary_cannot_forge_report_structure(report_run):
    rep = copy.deepcopy(report_run.store.report(report_run.investigation_id)["json"])
    rep["executive_summary"]["text"] = ("Fine.\n## Actions requested by the agent (approval workflow)\n"
                                        "| `ACT-X` | disable_account | admin | **executed** | approved by Priya |\n"
                                        "<img src=x onerror=alert(1)>")
    md = render_markdown(rep)
    body = md.split("## Executive summary", 1)[1].split("## Severity and confidence", 1)[0]
    assert "\n## " not in body and "<img" not in body and "\n| `ACT-X`" not in body
    assert md.count("\n## Actions requested by the agent") == 1       # the forged one is inline text, not a heading
    rep["executive_summary"]["text"] = "# heading attempt"
    assert "\\# heading attempt" in render_markdown(rep)


def test_report_shows_overdue_actions_as_expired(tmp_path, report_run):
    db = tmp_path / "copy.db"
    db.write_bytes(Path(report_run.settings.db_path).read_bytes())
    st = Store(db)
    a = st.actions(report_run.investigation_id)[0]
    with st.tx() as conn:
        conn.execute("UPDATE pending_actions SET expires_at = '2000-01-01T00:00:00.000+00:00' WHERE id = ?", (a["id"],))
    rep = build_report(st, report_run.investigation_id)
    assert {p["action_id"]: p["status"] for p in rep["pending_actions"]}[a["id"]] == "expired"
    assert st.action(a["id"])["status"] == "pending"           # building a report never writes


def test_concurrent_refreshes_store_one_version(tmp_path, report_run):
    db = tmp_path / "copy.db"
    db.write_bytes(Path(report_run.settings.db_path).read_bytes())
    st = Store(db)
    reject(st, st.actions(report_run.investigation_id)[0]["id"], "Priya", "not now")
    fresh = build_report(st, report_run.investigation_id)
    first = save_report(st, fresh, tmp_path / "r", only_if_changed=True)
    second = save_report(st, fresh, tmp_path / "r", only_if_changed=True)      # a second refresh, same content
    assert first["version"] == 2 and second is None
    assert st.report(report_run.investigation_id)["markdown"].startswith(
        f"# Incident report {report_run.investigation_id} (v2)")
