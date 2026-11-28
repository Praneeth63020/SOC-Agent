"""Generate docs/test-report.md from the recorded test results (no test is run here; nothing is invented).

    pytest --cov --cov-report=json:reports/coverage.json --junitxml=reports/junit.xml
    python scripts/run_scenarios.py                       # -> reports/scenarios-mock.json
    python scripts/make_test_report.py                    # -> docs/test-report.md

Inputs (each optional; a missing input is reported as "not run"):
  reports/junit.xml                      pytest results (totals, per file, safety tests)
  reports/coverage.json                  coverage (pytest-cov JSON report)
  reports/junit-run*.xml                 extra full-suite runs for the flaky-test check (scripts/check_flaky.sh)
  reports/scenarios-mock.json            the scenario matrix with the MOCK LLM (pipeline correctness)
  docs/results/scenarios-nvidia.json     the matrix against the real NVIDIA model (model quality)
  reports/cleanroom.json                 the clean-room verification (scripts/verify_clean_room.sh)
"""
from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
CATEGORY_TITLE = {"normal": "normal", "suspicious": "suspicious", "benign": "benign", "incomplete": "incomplete",
                  "tool_failure": "tool failure", "additional": "additional (Day 3)"}
SAFETY_FILES = ("test_bypass.py", "test_approvals.py", "test_api_and_security.py", "test_day5_hardening.py")


def _git() -> str:
    def run(*a):
        try:
            return subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    commit = run("rev-parse", "--short", "HEAD") or "unknown"
    dirty = run("status", "--porcelain")
    return f"`{commit}`" + (" + uncommitted changes in the working tree (the results are for the working tree)"
                            if dirty else "")


def _load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _cases(path: Path) -> list[dict]:
    """[{file, name, outcome, time, message}] from a junit XML file."""
    out = []
    root = ET.parse(path).getroot()
    for tc in root.iter("testcase"):
        cls = tc.get("classname", "")
        file = cls.split(".")[1] + ".py" if cls.startswith("tests.") else cls
        outcome, msg = "passed", ""
        for tag in ("failure", "error", "skipped"):
            el = tc.find(tag)
            if el is not None:
                outcome, msg = {"failure": "failed", "error": "error", "skipped": "skipped"}[tag], el.get("message", "")
        out.append({"file": file, "name": tc.get("name"), "outcome": outcome, "time": float(tc.get("time") or 0),
                    "message": msg})
    return out


def _yn(v) -> str:
    return {True: "yes", False: "no", None: "-"}[v]


def _actions(r: dict) -> str:
    acts = r.get("actions") or []
    return ", ".join(f"{a['action_type']} {a['target']}" for a in acts) if acts else "none"


def _expected(r: dict) -> str:
    e = r.get("expected") or {}
    c = {"requested": "containment requested", "none": "no containment"}.get(e.get("containment"), "")
    return f"{'/'.join(e.get('severity', []))}, confidence <= {e.get('confidence_max')}" + (f"; {c}" if c else "")


def section_tests(lines: list[str], cases: list[dict], cov: dict | None) -> None:
    by = defaultdict(lambda: defaultdict(int))
    times = defaultdict(float)
    for c in cases:
        by[c["file"]][c["outcome"]] += 1
        times[c["file"]] += c["time"]
    lines += ["## Unit and integration tests (pytest, offline, MOCK LLM only)", "",
              "| test file | passed | failed | skipped | time (s) |", "|---|---|---|---|---|"]
    for f in sorted(by):
        d = by[f]
        lines.append(f"| `{f}` | {d['passed']} | {d['failed'] + d['error']} | {d['skipped']} | {times[f]:.1f} |")
    bad = [c for c in cases if c["outcome"] in ("failed", "error")]
    if bad:
        lines += ["", "Failures:", ""] + [f"- `{c['file']}::{c['name']}`: {c['message'][:200]}" for c in bad]
    if cov:
        lines += ["", "### Coverage by module", "", "| module | statements | covered | % |", "|---|---|---|---|"]
        for f, d in sorted(cov["files"].items()):
            s = d["summary"]
            lines.append(f"| `{f.split('src/')[-1]}` | {s['num_statements']} | {s['covered_lines']} | "
                         f"{s['percent_covered']:.0f} |")
    lines.append("")


def section_matrix(lines: list[str], res: dict | None, title: str, model_quality: bool) -> None:
    lines += [f"## {title}", ""]
    if res is None:
        lines += ["**Not run** (no results file).", ""]
        return
    lines += [f"Provider **{res['provider']}** (`{res['model']}`), {res['started_at']} -> {res['finished_at']}, "
              f"{res['repeat']} run(s) per scenario, commit `{res['git']['commit']}`"
              + (" (working tree with uncommitted changes)" if res["git"]["dirty"] else "")
              + f". Fresh database `{res['database']}`; audit chain after the matrix: "
                f"**{'OK' if res['audit_ok'] else 'BROKEN'}**. **{res['passed']} of {res['total']} rows passed.**", ""]
    if res["mock"]:
        lines += ["MOCK LLM = a deterministic script, not an AI model. It applies the same rubric as the checks, so "
                  "these rows prove the **pipeline** (tool calls through Hermes, correlation, validation, rejection "
                  "and recovery, report, approval gate), not reasoning quality.", ""]
    rows = [r for r in res["rows"] if r["category"] not in ("safety", "rejection")]
    lines += ["| scenario | category | run | expected | actual severity / confidence | rubric severity / confidence "
              "| rubric agrees | containment requested | findings submissions | pass |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        subs = " -> ".join((r.get("submissions") or {}).get("submit_findings", [])) or "-"
        ok = "PASS" if not r["problems"] else "**FAIL**: " + "; ".join(r["problems"])[:300]
        if r.get("note"):
            ok += f" ({r['note']})"
        lines.append(f"| {r['scenario']} | {CATEGORY_TITLE.get(r['category'], r['category'])} | {r.get('run', 1)} | "
                     f"{_expected(r)} | {r.get('severity') or '-'} / {r.get('confidence') or '-'} | "
                     f"{r.get('rubric_severity', '-')} / {r.get('rubric_confidence', '-')} | {_yn(r.get('agrees'))} | "
                     f"{_actions(r)} | {subs} | {ok} |")
    special = [r for r in res["rows"] if r["category"] in ("safety", "rejection")]
    if special:
        lines += ["", "Rejection and safety runs (same pipeline, adversarial mock scripts):", "",
                  "| run | what must happen | result |", "|---|---|---|"]
        for r in special:
            ok = "PASS" if not r["problems"] else "**FAIL**: " + "; ".join(r["problems"])
            extra = (" - " + "; ".join(r["notes"])) if r.get("notes") else ""
            lines.append(f"| {r['title']} | {r.get('expected_text', '')} | {ok}{extra} |")
    if model_quality:
        by = defaultdict(list)
        for r in rows:
            by[r["scenario"]].append(r)
        lines += ["", "Per scenario:", "", "| scenario | passed runs | findings submissions per run | report phase |",
                  "|---|---|---|---|"]
        for name, rs in by.items():
            subs = "; ".join(str(len((r.get("submissions") or {}).get("submit_findings", []))) for r in rs)
            rep = ", ".join(r["status"]["report"] for r in rs)
            lines.append(f"| {name} | {sum(not r['problems'] for r in rs)} of {len(rs)} | {subs} | {rep} |")
        st = res.get("stats") or {}
        lines += ["", "Latency and tokens per phase over these runs (Hermes token counts as reported by the API):", "",
                  "| phase | seconds p50 | seconds max | input tokens p50 | input tokens max | output tokens p50 | "
                  "output tokens max |", "|---|---|---|---|---|---|---|"]
        for ph in ("plan", "assess", "report"):
            d = st.get(ph) or {}

            def v(k, q):
                return "-" if not d.get(k) else f"{d[k][q]:g}"
            lines.append(f"| {ph} | {v('seconds', 'p50')} | {v('seconds', 'max')} | {v('input_tokens', 'p50')} | "
                         f"{v('input_tokens', 'max')} | {v('output_tokens', 'p50')} | {v('output_tokens', 'max')} |")
        fails = [(r, f) for r in rows for f in r.get("validation_failures") or []]
        lines += ["", f"Rejected submissions (validation failures the model had to fix): {len(fails)}", ""]
        for r, f in fails[:40]:
            lines.append(f"- {r['scenario']} run {r['run']} `{f['tool']}`: "
                         + "; ".join(str(p) for p in f["problems"] if p)[:260])
        errs = [r for r in rows if r.get("error")]
        if errs:
            lines += ["", "Run errors:", ""] + [f"- {r['scenario']} run {r['run']} ({r['investigation_id']}): "
                                                 f"{str(r['error'])[:260]}" for r in errs]
    lines.append("")


def section_safety(lines: list[str], cases: list[dict]) -> None:
    lines += ["## Safety tests (pytest)", "",
              "Approval gate, toolset lockdown, prompt injection, analyst identity, audit tampering and API token. "
              "Each must pass; any failure is listed in the test table above.", "",
              "| test (parametrized cases collapsed) | cases | result |", "|---|---|---|"]
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for c in cases:
        if c["file"] in SAFETY_FILES:
            grouped[(c["file"], c["name"].split("[", 1)[0])].append(c["outcome"])
    for (f, name), outs in grouped.items():
        bad = [o for o in outs if o != "passed"]
        lines.append(f"| `{f}::{name}` | {len(outs)} | {'passed' if not bad else '**' + ', '.join(bad) + '**'} |")
    lines.append("")


def section_flaky(lines: list[str]) -> None:
    runs = sorted(REPORTS.glob("junit-run*.xml"))
    lines += ["## Flaky-test check", ""]
    if not runs:
        lines += ["**Not run** (`scripts/check_flaky.sh` runs the full suite 3 times).", ""]
        return
    outcomes = defaultdict(set)
    totals = []
    for p in runs:
        cs = _cases(p)
        totals.append(f"{p.name}: {sum(c['outcome'] == 'passed' for c in cs)} passed, "
                      f"{sum(c['outcome'] in ('failed', 'error') for c in cs)} failed")
        for c in cs:
            outcomes[(c["file"], c["name"])].add(c["outcome"])
    flaky = [k for k, v in outcomes.items() if len(v) > 1]
    lines += [f"The full suite ran {len(runs)} times: " + "; ".join(totals) + ".", "",
              (f"**{len(flaky)} flaky test(s):** " + ", ".join(f"`{f}::{n}`" for f, n in flaky)) if flaky
              else "No test changed outcome between runs: **no flaky tests found.**", ""]


def section_cleanroom(lines: list[str]) -> None:
    res = _load(REPORTS / "cleanroom.json")
    lines += ["## Clean-room verification", ""]
    if res is None:
        lines += ["**Not run** (`scripts/verify_clean_room.sh`).", ""]
        return
    lines += [f"{res['when']}: {res['source']} extracted into an empty temporary folder, new venv (Python "
              f"{res['python']}), `pip install -r requirements.txt` + `pip install -e .`, then:", "",
              "| step | result |", "|---|---|"]
    lines += [f"| {s['step']} | {'PASS' if s['ok'] else '**FAIL**'} {s.get('detail', '')} |" for s in res["steps"]]
    if any("skipped" in s.get("detail", "") for s in res["steps"]):
        lines += ["", "The skipped test checks that `.env` is not tracked by git; the extracted zip is not a git "
                      "checkout, so it is skipped there (it runs in the repository and in CI)."]
    lines.append("")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Write docs/test-report.md from recorded results")
    ap.add_argument("--out", default=str(ROOT / "docs" / "test-report.md"))
    args = ap.parse_args(argv)
    junit, cov = REPORTS / "junit.xml", _load(REPORTS / "coverage.json")
    cases = _cases(junit) if junit.is_file() else []
    mock, nvidia = _load(REPORTS / "scenarios-mock.json"), _load(ROOT / "docs" / "results" / "scenarios-nvidia.json")
    try:
        hv = version("hermes-agent")
    except PackageNotFoundError:
        hv = "not installed"
    passed = sum(c["outcome"] == "passed" for c in cases)
    failed = sum(c["outcome"] in ("failed", "error") for c in cases)
    pct = f"{cov['totals']['percent_covered']:.1f} %" if cov else "not measured"
    lines = [
        "# Test report",
        "",
        f"Generated by `python scripts/make_test_report.py` on "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} from the recorded results (nothing here is "
        "edited by hand). Commit: " + _git() + ".",
        "",
        f"Environment: Python {platform.python_version()}, {platform.platform(terse=True)}, hermes-agent {hv}. "
        "All data is **SYNTHETIC**; IP / CVE intelligence is a **MOCK** feed; nothing real is ever blocked, disabled "
        "or isolated (execution is SIMULATED).",
        "",
        "## Summary",
        "",
        "| what | result |",
        "|---|---|",
        f"| pytest (offline; never calls NVIDIA) | " + (f"**{passed} passed, {failed} failed**, "
                                                      f"{sum(c['outcome'] == 'skipped' for c in cases)} skipped, "
                                                      f"{sum(c['time'] for c in cases):.0f} s" if cases else "not run")
        + " |",
        f"| line coverage of src/soc_agent | {pct} |",
        f"| scenario matrix, MOCK LLM (pipeline correctness) | "
        + (f"{mock['passed']} of {mock['total']} rows passed" if mock else "not run") + " |",
        f"| scenario matrix, NVIDIA `{nvidia['model'] if nvidia else '-'}` (model quality) | "
        + (f"{nvidia['passed']} of {nvidia['total']} runs passed ({nvidia['repeat']} per scenario)" if nvidia
           else "**not run**") + " |",
        f"| CI on GitHub | not run from here: it runs on push (see `.github/workflows/ci.yml`) |",
        "",
        "Brief category -> scenario: **normal** -> `normal`; **suspicious** -> `compromise` (the main j.mehta case); "
        "**benign** -> `benign`; **incomplete** -> `incomplete`; **tool failure** -> `tool_failure` (lookup_ip "
        "times out) and `tool_failure_logs` (search_logs cannot read wazuh_alerts.jsonl). Additional Day 3 cases: "
        "`failures_only`, `conflicting`. Safety: approval bypass, forged approval, prompt-injection log line.",
        "",
    ]
    section_matrix(lines, mock, "Scenario matrix: MOCK LLM (pipeline correctness)", model_quality=False)
    section_matrix(lines, nvidia, "Scenario matrix: real model on NVIDIA (model quality)", model_quality=True)
    section_safety(lines, cases)
    section_flaky(lines)
    section_cleanroom(lines)
    if cases:
        section_tests(lines, cases, cov)
    else:
        lines += ["## Unit and integration tests", "", "**Not run** (no reports/junit.xml).", ""]
    Path(args.out).write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
