"""Test scenarios: SYNTHETIC data roots under data/scenarios/<name>/ and their expected outcomes in
tests/scenarios/<name>/expected.yaml. Used by the tests and by scripts/run_scenarios.py.

data/scenarios/<name>/scenario.json   {name, category, title, description, synthetic, faults, tool_timeout_s, ...}
                                      category = the brief's test category: normal | suspicious | benign |
                                      incomplete | tool_failure, or "additional"
data/scenarios/<name>/alert.json      the alert (normalized, synthetic: true)
data/scenarios/<name>/{logs,intel,assets}/   what the tools read for this scenario (RunContext.data_dir)
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from pathlib import Path

import yaml

from soc_agent.alerts import load_alert
from soc_agent.config import PROJECT_ROOT, Settings

SCENARIO_DIR = PROJECT_ROOT / "data" / "scenarios"
EXPECTED_DIR = PROJECT_ROOT / "tests" / "scenarios"
CONF_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Scenario:
    name: str
    root: Path
    manifest: dict
    alert: dict
    expected: dict

    @property
    def category(self) -> str:
        return self.manifest.get("category", "additional")

    def settings(self, base: Settings) -> Settings:
        """`base` reading this scenario's data root (and its tool timeout, if it sets one)."""
        changes = {"data_dir": self.root}
        if self.manifest.get("tool_timeout_s"):
            changes["tool_timeout_s"] = min(base.tool_timeout_s, float(self.manifest["tool_timeout_s"]))
        return dataclasses.replace(base, **changes)


ORDER = ("normal", "compromise", "benign", "incomplete", "tool_failure", "tool_failure_logs", "failures_only",
         "conflicting")
CATEGORIES = ("normal", "suspicious", "benign", "incomplete", "tool_failure", "additional")


def scenario_names() -> list[str]:
    found = {p.parent.name for p in SCENARIO_DIR.glob("*/scenario.json")}
    return [n for n in ORDER if n in found] + sorted(found - set(ORDER))


def load_scenario(name: str) -> Scenario:
    root = SCENARIO_DIR / name
    manifest = json.loads((root / "scenario.json").read_text(encoding="utf-8"))
    expected = yaml.safe_load((EXPECTED_DIR / name / "expected.yaml").read_text(encoding="utf-8"))
    return Scenario(name, root.resolve(), manifest, load_alert(root / "alert.json"), expected)


def _all_refs(findings: dict) -> set[str]:
    from soc_agent.tools.base import collect_refs
    return set(collect_refs(findings)) | set(findings.get("severity_evidence_refs", []))


def check_expected(assessment: dict, expected: dict, plan: dict | None, mock: bool) -> list[str]:
    """Every way the assessment misses the scenario's expectations (empty list = pass)."""
    f = assessment.get("findings")
    if not f:
        return [f"no accepted findings (status {assessment.get('status')})"]
    out = []
    if f["severity"] not in expected["severity"]:
        out.append(f"severity {f['severity']} not in {expected['severity']}")
    rub = assessment["rubric"]["severity"]["severity"]
    if mock and expected.get("rubric_severity") and rub != expected["rubric_severity"]:
        out.append(f"rubric severity {rub}, expected {expected['rubric_severity']}")
    if CONF_ORDER[f["confidence"]] > CONF_ORDER[expected["confidence_max"]]:
        out.append(f"confidence {f['confidence']} above the maximum {expected['confidence_max']}")
    # A plan may hold several competing benign explanations (user typo, stale script, ...): when "supported" is
    # expected, at least ONE of them must be supported; otherwise none may have a status outside the allowed ones.
    benign_ids = {h["id"] for h in (plan or {}).get("hypotheses", []) if h.get("benign")}
    allowed = expected.get("benign_hypothesis")
    benign = {h["id"]: h["status"] for h in f["hypotheses"] if h["id"] in benign_ids}
    if allowed and benign:
        if "supported" in allowed:
            if "supported" not in benign.values():
                out.append(f"no benign hypothesis is supported ({benign}), expected one of them supported")
        elif bad := {i: st for i, st in benign.items() if st not in allowed}:
            out.append(f"benign hypothesis {', '.join(f'{i} is {st}' for i, st in bad.items())}, expected {allowed}")
    cited = _all_refs(f)
    for ref in expected.get("must_cite", []):
        if ref not in cited:
            out.append(f"{ref} is not cited")
    for prefix in expected.get("must_not_cite_prefix", []):
        if bad := sorted(r for r in cited if r.startswith(prefix)):
            out.append(f"cites {bad[0]} although no such evidence can exist in this run")
    used = {m["technique_id"] for m in f["mitre"]}
    for t in expected.get("mitre_required", []):          # a sub-technique (T1078.003) satisfies its parent (T1078)
        if not any(u == t or u.startswith(t + ".") for u in used):
            out.append(f"MITRE {t} (or a sub-technique of it) expected")
    for t in expected.get("mitre_forbidden", []):
        if t in used:
            out.append(f"MITRE {t} is not justified here")
    for key, items, label in (("required_gaps", [g["id"] + " " + g["statement"] for g in assessment["gaps"]], "gap"),
                              ("required_unknowns", f["unknowns"], "unknown"),
                              ("required_conflicts", [c["statement"] for c in assessment["conflicts"]], "conflict")):
        for word in expected.get(key, []):
            if not any(word.lower() in x.lower() for x in items):
                out.append(f"no {label} mentions {word!r}")
    return out


def check_containment(expected: dict, actions: list[dict]) -> list[str]:
    """expected["containment"]: "requested" (at least one action request), "none" (no request) or "any"."""
    want = expected.get("containment", "any")
    if want == "requested" and not actions:
        return ["no containment action was requested, expected at least one (pending for an analyst)"]
    if want == "none" and actions:
        return [f"containment requested ({', '.join(a['action_type'] + ' ' + a['target'] for a in actions)}), "
                "expected none"]
    return []
