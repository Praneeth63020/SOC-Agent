"""HTTP API, configuration and secret handling."""
import importlib.util
import re
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from soc_agent.api import app
from soc_agent.config import ConfigError, load_settings

ROOT = Path(__file__).resolve().parent.parent
client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["hermes_agent"] == "0.19.0"


def test_validate_endpoint(wazuh_raw, alert):
    r = client.post("/alerts/validate", json=wazuh_raw)
    assert r.status_code == 200 and r.json()["entities"]["account"] == "j.mehta" and "raw" not in r.json()
    bad = {k: v for k, v in alert.items()} | {"extra": 1}
    r = client.post("/alerts/validate", json=bad)
    assert r.status_code == 422 and "extra" in r.json()["detail"]
    assert client.post("/alerts/validate", json={"foo": 1}).status_code == 422
    assert client.post("/alerts/validate", content=b"{not json",
                       headers={"Content-Type": "application/json"}).status_code == 422


def test_plan_endpoint_and_run_record(wazuh_raw, mock_settings):
    r = client.post("/alerts/plan?provider=mock", json=wazuh_raw)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "planned" and body["plan"]["generated_by"]["mock"] is True
    run = client.get(f"/runs/{body['investigation_id']}")
    assert run.status_code == 200 and [c["tool"] for c in run.json()["tool_calls"]] == [
        "get_alert", "submit_investigation_plan"]
    assert client.get("/runs/INV-20990101-DEADBEEF").status_code == 404


def test_plan_endpoint_errors(alert, mock_settings):
    clean = {k: v for k, v in alert.items() if k != "raw"}
    assert client.post("/alerts/plan?provider=openai", json=clean).status_code == 422
    r = client.post("/alerts/plan?provider=nvidia", json=clean)            # no key in tests
    assert r.status_code == 503 and "NVIDIA_API_KEY" in r.json()["detail"]


@pytest.mark.parametrize("path", ["/runs/..%2F..%2Fetc%2Fpasswd", "/runs/%2e%2e%2fpyproject.toml",
                                  "/runs/..", "/runs/../pyproject.toml", "/runs/INV-20261120-DEADBEEF%2F..%2F.."])
def test_run_lookup_blocks_path_traversal(path, mock_settings):
    r = client.get(path)
    assert r.status_code in (400, 404) and "cehpoint-soc-agent" not in r.text


@pytest.mark.parametrize("run_id", ["INV-20261120-DEADBEEF.json", "inv-20261120-deadbeef", "INV-20261120-DEADBEE",
                                    "INV-2026112-DEADBEEF0", "INV-20261120-DEADBEEF%0A", "...."])
def test_run_lookup_rejects_malformed_ids(run_id, mock_settings):
    assert client.get(f"/runs/{run_id}").status_code == 400


def test_missing_nvidia_key_is_a_clear_error():
    with pytest.raises(ConfigError, match="NVIDIA_API_KEY is not set.*--provider mock"):
        load_settings("nvidia")


def test_nvidia_settings_from_env(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key-not-real")
    s = load_settings("nvidia")
    assert s.base_url == "https://integrate.api.nvidia.com/v1" and s.model == "meta/llama-3.3-70b-instruct"
    assert not s.is_mock and s.api_key == "test-key-not-real"


@pytest.mark.parametrize("var, value", [("SOC_MAX_ITERATIONS", "lots"), ("SOC_MAX_ITERATIONS", "500"),
                                        ("SOC_MAX_TOKENS", "-1"), ("SOC_LLM_PROVIDER", "openai")])
def test_bad_config_is_a_clear_error(monkeypatch, var, value):
    monkeypatch.setenv(var, value)
    with pytest.raises(ConfigError, match=var if var != "SOC_LLM_PROVIDER" else "Unknown SOC_LLM_PROVIDER"):
        load_settings()


def test_env_is_ignored_and_example_has_no_secrets():
    ignore = (ROOT / ".gitignore").read_text().splitlines()
    for entry in (".env", "!.env.example", ".hermes/", "runs/"):
        assert entry in ignore
    for line in (ROOT / ".env.example").read_text().splitlines():
        if re.match(r"^\s*[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD)\s*=", line):
            assert line.split("=", 1)[1].strip() == "", line


def test_git_ignores_env_files():
    r = subprocess.run(["git", "check-ignore", "-q", ".env"], cwd=ROOT)
    if r.returncode == 128:
        pytest.skip("not a git checkout")
    assert r.returncode == 0
    assert subprocess.run(["git", "check-ignore", "-q", ".env.example"], cwd=ROOT).returncode == 1


def _scanner():
    spec = importlib.util.spec_from_file_location("check_secrets", ROOT / "scripts" / "check_secrets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_secret_scanner_is_clean_on_the_repo():
    assert _scanner().scan(ROOT) == []


@pytest.mark.parametrize("line", [
    'KEY = "nvapi-' + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4" + '"',
    "NVIDIA_API_KEY=nvapi-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2",
    'api_key: "' + "s3cr3tV4lu3-0123456789ab" + '"',
    "password = '" + "hunter2hunter2hunter2" + "'",
])
def test_secret_scanner_detects_keys(tmp_path, line):
    (tmp_path / "x.py").write_text(line + "\n")
    assert _scanner().scan(tmp_path)


def test_secret_scanner_ignores_empty_and_placeholder_values(tmp_path):
    (tmp_path / "x.env.example").write_text("NVIDIA_API_KEY=\nSOC_LLM_PROVIDER=mock\n")
    (tmp_path / "y.py").write_text('api_key = os.environ.get("NVIDIA_API_KEY")\n')
    assert _scanner().scan(tmp_path) == []
