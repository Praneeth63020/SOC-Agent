import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from soc_agent.alerts import load_alert
from soc_agent.config import load_settings

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "data" / "alerts"
CLEARED_VARS = ("SOC_FAULTS", "SOC_TOOL_TIMEOUT_S", "SOC_DATA_DIR", "SOC_INVESTIGATION_MAX_ITERATIONS",
                "SOC_ASSESSMENT_MAX_ITERATIONS", "SOC_ASSESSMENT_MAX_TOKENS", "SOC_REPORT_MAX_ITERATIONS",
                "SOC_MAX_ITERATIONS", "SOC_MAX_TOKENS", "SOC_API_MAX_RETRIES")


def offline_env(mp: pytest.MonkeyPatch, root: Path) -> None:
    """Tests never call NVIDIA: no key, no .env, and provider forced to mock. State (SQLite history, reports,
    simulated-action log) goes to the test's own tmp dir, never to state/, reports/ or data/."""
    mp.setattr("soc_agent.config.load_dotenv", lambda *a, **k: None)
    mp.delenv("NVIDIA_API_KEY", raising=False)
    mp.delenv("ANALYST_API_TOKEN", raising=False)
    mp.setenv("SOC_DB_PATH", str(root / "state" / "soc.db"))
    mp.setenv("SOC_REPORTS_DIR", str(root / "reports"))
    mp.setenv("SOC_SIMULATED_ACTIONS_LOG", str(root / "simulated_actions.log"))
    mp.setenv("SOC_LLM_PROVIDER", "mock")
    for var in CLEARED_VARS:
        mp.delenv(var, raising=False)        # the developer's shell must not change test results


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    offline_env(monkeypatch, tmp_path)


@pytest.fixture
def alert():
    return load_alert(ALERTS / "account_compromise.json")


@pytest.fixture
def wazuh_raw():
    return json.loads((ALERTS / "wazuh_account_compromise.json").read_text())


@pytest.fixture
def mock_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("SOC_HERMES_HOME", str(tmp_path / "hermes"))
    return load_settings("mock")


# ------------------------------------------------------------------ Day 4: one full mock run per report script
@dataclass
class Day4Run:
    settings: object
    plan: object
    assessment: object
    report: object
    store: object

    @property
    def investigation_id(self) -> str:
        return self.plan.investigation_id

    def calls(self, phase: str = "report") -> list[dict]:
        return [c for c in self.store.tool_calls(self.investigation_id) if c["phase"] == phase]


def _day4_run(tmp_path_factory, report_scenario: str) -> Day4Run:
    from soc_agent.reporter import run_alert
    from soc_agent.store import Store

    root = tmp_path_factory.mktemp(report_scenario)
    with pytest.MonkeyPatch.context() as mp:
        offline_env(mp, root)
        mp.setenv("SOC_RUNS_DIR", str(root / "runs"))
        mp.setenv("SOC_HERMES_HOME", str(root / "hermes"))
        settings = load_settings("mock")
        plan, assessment, report = run_alert(load_alert(ALERTS / "account_compromise.json"), settings,
                                             report_scenario=report_scenario)
    return Day4Run(settings, plan, assessment, report, Store(settings.db_path))


@pytest.fixture(scope="module")
def report_run(tmp_path_factory) -> Day4Run:
    return _day4_run(tmp_path_factory, "report")


@pytest.fixture(scope="module")
def bypass_run(tmp_path_factory) -> Day4Run:
    return _day4_run(tmp_path_factory, "report_bypass")


@pytest.fixture(scope="module")
def injection_run(tmp_path_factory) -> Day4Run:
    return _day4_run(tmp_path_factory, "report_injection")
