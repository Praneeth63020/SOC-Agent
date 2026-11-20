import json
from pathlib import Path

import pytest

from soc_agent.alerts import load_alert
from soc_agent.config import load_settings

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "data" / "alerts"


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """Tests never call NVIDIA: no key, no .env, and provider forced to mock."""
    monkeypatch.setattr("soc_agent.config.load_dotenv", lambda *a, **k: None)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.setenv("SOC_LLM_PROVIDER", "mock")


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
