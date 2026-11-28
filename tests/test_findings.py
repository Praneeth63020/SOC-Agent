"""Day 3 submit_findings validation, called directly through the wrapper (no Hermes, no LLM)."""
import copy
import json

import pytest

from soc_agent.correlate import correlate
from soc_agent.mock_llm import build_mock_findings, build_mock_plan
from soc_agent.schemas import load_schema, problems
from soc_agent.severity import rubric
from soc_agent.tools.assessment import MAX_FINDINGS_ATTEMPTS, SUBMIT_FINDINGS, mitre_catalog
from soc_agent.tools.base import RunContext, call_tool
from soc_agent.tools.evidence import GET_ASSET_CONTEXT, LOOKUP_IP, SEARCH_LOGS

ATTACKER, OUTBOUND = "203.0.113.77", "198.51.100.23"
SUCCESS, FAIL, SUDO = "wazuh_alerts.jsonl#L64", "wazuh_alerts.jsonl#L63", "wazuh_alerts.jsonl#L65"


def make_ctx(alert, faults=None):
    ctx = RunContext("INV-TEST-FINDINGS", alert, plan=build_mock_plan(alert), faults=faults or {}, tool_timeout_s=0.3)
    for spec, args in [(SEARCH_LOGS, {"source": "wazuh", "account": "j.mehta", "host": "fin-app-01",
                                      "start": "2026-11-11T00:00:00Z", "end": "2026-11-18T12:00:00Z", "limit": 200}),
                       (SEARCH_LOGS, {"source": "all", "src_ip": ATTACKER, "limit": 200}),
                       (LOOKUP_IP, {"ip": ATTACKER}), (GET_ASSET_CONTEXT, {"host": "fin-app-01"}),
                       (GET_ASSET_CONTEXT, {"account": "j.mehta"}),
                       (SEARCH_LOGS, {"source": "all", "host": "fin-app-01", "start": "2026-11-18T09:42:17Z"}),
                       (LOOKUP_IP, {"ip": OUTBOUND})]:
        call_tool(spec, args, ctx)
    return ctx


def valid(ctx):
    c = correlate(ctx.alert, ctx.evidence_results, ctx.tool_calls)
    return build_mock_findings(c, rubric(c), ctx.plan, ctx.alert)


@pytest.fixture
def ctx(alert):
    return make_ctx(alert)


@pytest.fixture
def failed_ctx(alert):
    return make_ctx(alert, faults={"lookup_ip": "timeout"})


def submit(ctx, findings):
    out, entry = call_tool(SUBMIT_FINDINGS, findings, ctx)
    return out, entry["status"]


def rejected_with(ctx, findings, needle):
    out, status = submit(ctx, findings)
    assert status == "rejected" and ctx.findings is None, out
    assert needle in json.dumps(out), json.dumps(out, indent=1)[:3000]
    return out


# ------------------------------------------------------------------------------- accept
def test_valid_findings_are_accepted_once_and_checked_against_the_rubric(ctx):
    f = valid(ctx)
    assert problems(f, load_schema("findings")) == []
    out, status = submit(ctx, f)
    assert status == "ok" and out["accepted"] is True and ctx.findings == f
    chk = out["severity_check"]
    assert chk == ctx.findings_check["severity_check"]
    assert chk["agent_severity"] == chk["rubric_severity"] == "critical" and chk["agrees"] is True
    assert ctx.findings_check["rubric"]["confidence"]["confidence"] == "high"
    out, status = submit(ctx, f)
    assert status == "rejected" and "already accepted" in out["error"]


def test_attempts_are_limited(ctx):
    bad = valid(ctx)
    bad["timeline"][0]["evidence_refs"] = ["wazuh_alerts.jsonl#L999"]
    for _ in range(MAX_FINDINGS_ATTEMPTS):
        assert submit(ctx, bad)[1] == "rejected"
    out, status = submit(ctx, valid(ctx))
    assert status == "rejected" and "Too many findings submissions" in out["error"]


# ------------------------------------------------------------------------- refs, claims
def test_unknown_ref_is_rejected(ctx):
    f = valid(ctx)
    f["timeline"][0]["evidence_refs"].append("wazuh_alerts.jsonl#L999")
    rejected_with(ctx, f, "timeline claim 1: evidence_ref 'wazuh_alerts.jsonl#L999' was not returned by any tool "
                          "in this run")


def test_a_ref_that_exists_in_the_data_but_was_not_returned_is_rejected(ctx):
    f = valid(ctx)                     # line 4 exists in the file (scanner noise) but no search returned it
    f["related_events"][0]["evidence_refs"] = ["wazuh_alerts.jsonl#L4"]
    rejected_with(ctx, f, "'wazuh_alerts.jsonl#L4' was not returned by any tool in this run")


def test_claim_without_ref_is_rejected(ctx):
    f = valid(ctx)
    f["account_and_asset"].append({"statement": "The attacker is probably a criminal group.", "evidence_refs": []})
    rejected_with(ctx, f, "account_and_asset claim 3: claim has no evidence_refs; cite the refs it rests on, or move "
                          "the statement to unknowns")


def test_unknowns_need_no_refs(ctx):
    f = valid(ctx)
    f["unknowns"].append("Whether the attacker kept other footholds is unknown.")
    assert submit(ctx, f)[1] == "ok"


def test_severity_needs_evidence(ctx):
    f = valid(ctx)
    f["severity_evidence_refs"] = []
    rejected_with(ctx, f, "severity_evidence_refs: cite at least one evidence_ref")


# --------------------------------------------------------------------------------- MITRE
@pytest.mark.parametrize("entry, needle", [
    ({"technique_id": "T9999", "name": "Made Up", "justification": "No such technique.", "evidence_refs": [SUCCESS]},
     "mitre T9999: not in the local MITRE catalog"),
    ({"technique_id": "T1078", "name": "Valid Accounts", "justification": "Cites only a failure.",
      "evidence_refs": [FAIL]}, "mitre T1078: none of the cited refs is a auth_success event"),
    ({"technique_id": "T1078", "name": "Valid Accounts", "justification": "No evidence.", "evidence_refs": []},
     "mitre T1078: cite the events that justify this technique"),
    ({"technique_id": "T1548.003", "name": "Sudo Abuse", "justification": "sudo to root.", "evidence_refs": [SUDO]},
     "name should be 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching'"),
    ({"technique_id": "T1110.003", "name": "Password Spraying", "justification": "One account only.",
      "evidence_refs": [FAIL, "wazuh_alerts.jsonl#L12"]}, "cite failed logins for at least 2 different accounts"),
], ids=["not-in-catalog", "wrong-evidence-kind", "no-refs", "wrong-name", "spraying-one-account"])
def test_mitre_must_be_in_the_catalog_and_justified(ctx, entry, needle):
    f = valid(ctx)
    f["mitre"].append(entry)
    rejected_with(ctx, f, needle)


def test_mitre_short_name_and_catalog():
    cat = mitre_catalog()
    assert {"T1110", "T1110.001", "T1110.003", "T1078", "T1021.004", "T1136.001", "T1548.003", "T1071.001"} <= set(cat)
    assert all(t["name"] and t["requires_event_types"] for t in cat.values())


def test_mitre_subtechnique_short_name_is_accepted(ctx):
    f = valid(ctx)
    f["mitre"] = [{"technique_id": "T1110.001", "name": "Password Guessing", "justification": "50 failed logins.",
                   "evidence_refs": [FAIL]}]
    assert submit(ctx, f)[1] == "ok"


# ----------------------------------------------------------- gaps -> unknowns, confidence
def test_high_confidence_with_a_timed_out_tool_is_rejected(failed_ctx):
    f = valid(failed_ctx)
    f.update(confidence="high", unknowns=[])
    out = rejected_with(failed_ctx, f, "confidence: cannot be high while evidence is missing, failed, timed out")
    text = json.dumps(out)
    assert "unknowns: must not be empty - the correlation found gaps" in text and "timed out" in text


def test_findings_with_stated_uncertainty_are_accepted_after_a_timeout(failed_ctx):
    f = valid(failed_ctx)
    assert f["confidence"] == "medium" and any("unknown" in u for u in f["unknowns"])
    assert submit(failed_ctx, f)[1] == "ok"


def test_unresolved_conflict_forbids_high_confidence(alert):
    changed = {**alert, "observations": {**alert["observations"], "failed_attempts": 40}}
    c = make_ctx(changed)
    f = valid(c)
    f["confidence"] = "high"
    rejected_with(c, f, "confidence: cannot be high")


# ------------------------------------------------------------------------ IP reputation
def test_reputation_claim_without_mock_label_is_rejected(ctx):
    f = valid(ctx)
    f["source_ip_intelligence"] = [{"statement": f"{ATTACKER} is classified malicious with score 92.",
                                    "evidence_refs": [f"ip_reputation.json#{ATTACKER}"]}]
    rejected_with(ctx, f, "does not say it is MOCK intel")


def test_reputation_claim_without_lookup_ref_is_rejected(ctx):
    f = valid(ctx)
    f["source_ip_intelligence"] = [{"statement": f"Threat intelligence (MOCK) says {ATTACKER} is malicious.",
                                    "evidence_refs": [SUCCESS]}]
    rejected_with(ctx, f, f"does not cite ip_reputation.json#{ATTACKER}")


def test_verdict_without_any_intel_ref_is_rejected(ctx):
    f = valid(ctx)
    f["severity_justification"].append({"statement": "Intel shows the source is known-bad.", "evidence_refs": [FAIL]})
    rejected_with(ctx, f, "states an intelligence verdict without citing a lookup_ip ref")


def test_reputation_after_a_failed_lookup_must_go_to_unknowns(failed_ctx):
    f = valid(failed_ctx)
    f["source_ip_intelligence"].append({"statement": f"The reputation of {ATTACKER} is probably bad.",
                                        "evidence_refs": [SUCCESS]})
    rejected_with(failed_ctx, f, f"lookup_ip for {ATTACKER} failed or timed out in this run (no data). State this in "
                                 "unknowns")


# ------------------------------------------------------------------------------ severity
def _disagree(f):
    f = copy.deepcopy(f)
    f["severity"] = "high"                                   # one level below the rubric's critical
    f["severity_rationale"] = "Looks less bad to me than the alert suggests."
    f["severity_evidence_refs"] = [SUCCESS, SUDO]          # log evidence only (no intel ref, so no MOCK wording needed)
    return f


def test_severity_disagreement_without_rationale_is_rejected_once_with_the_rubric_factors(ctx):
    f = _disagree(valid(ctx))
    out = rejected_with(ctx, f, "severity: high differs from the rubric (critical, rule C1")
    assert "Rubric factors:" in out["problems"][0] and "privileged action" in out["problems"][0]
    out, status = submit(ctx, f)           # rejected only once: then accepted and recorded, never overwritten
    assert status == "ok" and ctx.findings["severity"] == "high"
    chk = out["severity_check"]
    assert chk["agrees"] is False and chk["rubric_severity"] == "critical" and chk["accepted_after_rubric_hint"]


def test_severity_disagreement_that_addresses_the_rubric_is_accepted(ctx):
    f = _disagree(valid(ctx))
    f["severity_rationale"] = ("The rubric says critical, but the sudo session lasted seconds; I rate it high "
                               "pending host forensics.")
    out, status = submit(ctx, f)
    assert status == "ok" and out["severity_check"]["agrees"] is False
    assert out["severity_check"]["rationale_addresses_rubric"] is True
    assert ctx.findings_check["rubric"]["severity"]["severity"] == "critical"     # the rubric is kept separately


@pytest.mark.parametrize("severity", ["medium", "low"])
def test_severity_more_than_one_level_from_the_rubric_is_rejected_every_time(ctx, severity):
    f = _disagree(valid(ctx))
    f.update(severity=severity, severity_rationale=f"The rubric says critical, but I rate it {severity}.")
    for _ in range(2):                                       # not a one-time hint: a hard bound
        rejected_with(ctx, f, f"severity: {severity} is ")
    assert ctx.findings is None


# ---------------------------------------------------------------- hypotheses, next steps
@pytest.mark.parametrize("change, needle", [
    (lambda f: f["hypotheses"].pop(), "missing plan hypothesis id(s) ['H3']"),
    (lambda f: f["hypotheses"].append({**f["hypotheses"][0], "id": "H9"}), "['H9'] are not hypotheses of the plan"),
    (lambda f: f["hypotheses"].append(dict(f["hypotheses"][0])), "H1 appears more than once"),
    (lambda f: f["hypotheses"][0].update(evidence_refs=[]), "hypothesis H1: status supported needs at least one"),
    (lambda f: f["recommended_next_steps"].append({"action": "Block 203.0.113.77 now.", "type": "containment",
                                                   "rationale": "It is bad.", "requires_approval": False}),
     "needs requires_approval: true (nothing is executed)"),
], ids=["missing-hypothesis", "extra-hypothesis", "duplicate", "supported-without-refs", "containment-no-approval"])
def test_hypotheses_and_next_steps(ctx, change, needle):
    f = valid(ctx)
    change(f)
    rejected_with(ctx, f, needle)


def test_undetermined_hypothesis_may_have_no_refs(ctx):
    f = valid(ctx)
    f["hypotheses"][1].update(status="undetermined", evidence_refs=[])
    assert submit(ctx, f)[1] == "ok"


# ----------------------------------------------------------------------------- schema
@pytest.mark.parametrize("change, needle", [
    (lambda f: f.update(verdict="compromised"), "'verdict' was unexpected"),
    (lambda f: f.update(severity="urgent"), "'urgent' is not one of"),
    (lambda f: f.update(confidence="certain"), "'certain' is not one of"),
    (lambda f: f.pop("unknowns"), "'unknowns' is a required property"),
    (lambda f: f.update(timeline=[]), "should be non-empty"),
    (lambda f: f["timeline"][0].update(evidence_refs=["not a ref"]), "'not a ref' is not valid (an evidence_ref"),
    (lambda f: f.update(timeline=json.dumps(f["timeline"])[:-3]), "timeline: must be a JSON array, not a string"),
], ids=["extra-field", "bad-severity", "bad-confidence", "missing", "empty-answer", "bad-ref", "json-string"])
def test_schema_problems_are_rejected_by_the_wrapper(ctx, change, needle):
    f = valid(ctx)
    change(f)
    rejected_with(ctx, f, needle)


def test_model_gets_a_simplified_schema_with_top_level_arrays():
    sent = SUBMIT_FINDINGS.hermes_schema()["parameters"]
    text = json.dumps(sent)
    assert '"pattern"' not in text and '"$ref"' not in text and '"enum"' in text
    assert sent["properties"]["timeline"]["type"] == "array" and "findings" not in sent["properties"]
    assert '"pattern"' in json.dumps(SUBMIT_FINDINGS.parameters)
    assert SUBMIT_FINDINGS.permission == "write_internal"


# ------------------------------------------- resubmission: missing fields from the previous attempt
def test_a_resubmission_may_leave_out_fields_of_the_previous_attempt(ctx):
    f = valid(ctx)
    bad = copy.deepcopy(f)
    bad["timeline"][0]["evidence_refs"] = ["wazuh_alerts.jsonl#L999"]
    assert submit(ctx, bad)[1] == "rejected"
    fixed = {k: v for k, v in f.items() if k not in ("hypotheses", "mitre")}     # a live model dropped fields
    out, status = submit(ctx, fixed)
    assert status == "ok", out
    assert out["notes"] == ["Fields missing from this submission were taken from your previous submission: "
                            "hypotheses, mitre."]
    assert ctx.findings == f                                       # the merged findings, fully validated
    assert "hypotheses" not in ctx.tool_calls[-1]["arguments"]     # the audit keeps what the model actually sent


def test_carried_over_fields_are_validated_like_new_ones(ctx):
    f = valid(ctx)
    bad = copy.deepcopy(f)
    bad["mitre"].append({"technique_id": "T9999", "name": "Made Up", "justification": "No such technique.",
                         "evidence_refs": [SUCCESS]})
    assert submit(ctx, bad)[1] == "rejected"
    out, status = submit(ctx, {k: v for k, v in f.items() if k != "mitre"})   # the flawed mitre is NOT reused
    assert status == "rejected" and "'mitre' is a required property" in json.dumps(out)
    assert "Not taken from your previous submission because they had problems: mitre" in json.dumps(out)


def test_a_first_submission_with_missing_fields_is_rejected(ctx):
    f = valid(ctx)
    del f["hypotheses"]
    out, status = submit(ctx, f)
    assert status == "rejected" and "'hypotheses' is a required property" in json.dumps(out)
    assert "all 16 fields" in out["hint"]


# ------------------------------------------------- regression: loopholes found in review
@pytest.mark.parametrize("statement", [
    f"Its reputation is bad: we know about {ATTACKER}.",                 # IP at the end of a sentence
    f"{ATTACKER} is a known malicious scanner.",                          # a verdict without the word "intel"
    f"The malicious source {ATTACKER} kept trying.",
])
def test_reputation_after_a_failed_lookup_is_caught_in_any_wording(failed_ctx, statement):
    f = valid(failed_ctx)
    f["related_events"].append({"statement": statement, "evidence_refs": [SUCCESS]})
    rejected_with(failed_ctx, f, f"talks about the reputation of {ATTACKER}, but lookup_ip for {ATTACKER} failed")


def test_plain_log_statements_about_an_ip_are_not_reputation_claims(failed_ctx):
    f = valid(failed_ctx)
    f["related_events"].append({"statement": f"{ATTACKER} made 53 failed logins and one successful login.",
                                "evidence_refs": [SUCCESS, FAIL]})
    assert submit(failed_ctx, f)[1] == "ok"


def test_reputation_in_hypothesis_reasoning_and_mitre_justification_is_checked(ctx):
    f = valid(ctx)
    f["hypotheses"][0]["reasoning"] = f"{ATTACKER} has a malicious reputation in threat intelligence."
    rejected_with(ctx, f, f"hypothesis H1 reasoning: talks about the reputation of {ATTACKER} but does not cite")
    f = valid(ctx)
    f["mitre"][0]["justification"] = "Failed logins from a source the intel feed lists as malicious."
    f["mitre"][0]["evidence_refs"] = f["mitre"][0]["evidence_refs"] + [f"ip_reputation.json#{ATTACKER}"]
    rejected_with(ctx, f, "justification: cites IP intelligence")


@pytest.mark.parametrize("action", ["Block 203.0.113.77 at the firewall.", "Disable j.mehta.",
                                    "Isolate fin-app-01 from the network.", "Reset j.mehta's password."])
def test_containment_cannot_be_labelled_investigative(ctx, action):
    f = valid(ctx)
    f["recommended_next_steps"].append({"action": action, "type": "investigative", "rationale": "Stop the attacker.",
                                        "requires_approval": False})
    rejected_with(ctx, f, "is a containment action; set type containment and requires_approval: true")
