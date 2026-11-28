"""Settings from environment / .env. Secrets are only ever read from the environment."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]

NVIDIA_DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
# meta/llama-3.3-70b-instruct (named in the brief) is no longer listed on NVIDIA's API (checked 2026-11-20);
NVIDIA_DEFAULT_MODEL = "nvidia/nemotron-3.5-lightning-30b-a3b"   # verified live with tool calling
MOCK_MODEL = "mock-soc-planner"
PROVIDERS = ("nvidia", "mock")
FAULT_KINDS = ("timeout", "error", "malformed")     # SOC_FAULTS: tests and demos only


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    llm_provider: str            # "nvidia" (real model) | "mock" (offline deterministic script)
    base_url: str                # empty for mock: filled in when the in-process server starts
    api_key: str | None
    model: str
    max_tokens: int = 4096       # a full plan is one tool call; ~1.5k tokens for the mock's 7 steps
    max_iterations: int = 9      # planning phase step limit: get_alert + up to 3 checked + 3 format-rejected plans
    investigation_max_iterations: int = 20   # investigation phase: one round per evidence tool call (+ retries)
    assessment_max_iterations: int = 28      # assessment phase: evidence calls, follow-ups, correlate, findings (+ retries)
    report_max_iterations: int = 16          # report phase: action requests, report content (+ retries)
    assessment_max_tokens: int = 8192        # findings are one large tool call (~3k tokens) plus the model's reasoning
    tool_timeout_s: float = 5.0  # per tool call; a slower call returns status "timeout" and no data
    api_max_retries: int = 6     # Hermes retries per LLM call (HTTP 429 / 5xx, backoff up to 60 s); Hermes default 3
    hermes_home: Path = PROJECT_ROOT / ".hermes"   # isolated Hermes state, git-ignored
    runs_dir: Path = PROJECT_ROOT / "runs"         # run records (JSON), git-ignored
    data_dir: Path = PROJECT_ROOT / "data"         # SYNTHETIC logs / assets, MOCK intel
    db_path: Path = PROJECT_ROOT / "state" / "soc.db"   # investigation history + audit trail (SQLite), git-ignored
    reports_dir: Path = PROJECT_ROOT / "reports"        # rendered incident reports (JSON + Markdown), git-ignored
    faults: dict = field(default_factory=dict)     # fault injection {tool: kind}; empty in normal use

    @property
    def is_mock(self) -> bool:
        return self.llm_provider == "mock"


def _load_env() -> None:
    load_dotenv(PROJECT_ROOT / ".env")      # never overrides variables already set


def _int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {value}")
    return value


def _float(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from None
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo:g} and {hi:g}, got {value:g}")
    return value


def parse_faults(spec: str) -> dict[str, str]:
    """'lookup_ip:timeout,search_cve:error' -> {'lookup_ip': 'timeout', 'search_cve': 'error'}."""
    faults: dict[str, str] = {}
    for part in (p.strip() for p in (spec or "").split(",")):
        if not part:
            continue
        tool, sep, kind = (x.strip() for x in part.partition(":"))
        if not sep or not tool or kind not in FAULT_KINDS:
            raise ConfigError(f"Bad fault {part!r}: use tool:kind with kind one of {', '.join(FAULT_KINDS)} "
                              "(e.g. SOC_FAULTS=lookup_ip:timeout)")
        faults[tool] = kind
    return faults


def _path(name: str, default: Path) -> Path:
    raw = os.environ.get(name, "").strip()
    p = Path(raw).expanduser() if raw else default
    return p if p.is_absolute() else PROJECT_ROOT / p


def runs_dir() -> Path:
    _load_env()
    return _path("SOC_RUNS_DIR", PROJECT_ROOT / "runs")


def db_path() -> Path:
    _load_env()
    return _path("SOC_DB_PATH", PROJECT_ROOT / "state" / "soc.db")


def reports_dir() -> Path:
    _load_env()
    return _path("SOC_REPORTS_DIR", PROJECT_ROOT / "reports")


def simulated_actions_log() -> Path:
    """Where SIMULATED executions of approved actions are logged (nothing real is ever changed)."""
    _load_env()
    return _path("SOC_SIMULATED_ACTIONS_LOG", PROJECT_ROOT / "data" / "simulated_actions.log")


def analyst_api_token() -> str:
    """ANALYST_API_TOKEN for the analyst endpoints of the API ('' = not configured: those endpoints answer 503)."""
    _load_env()
    return os.environ.get("ANALYST_API_TOKEN", "").strip()


def load_settings(provider: str | None = None) -> Settings:
    _load_env()
    env = os.environ
    provider = (provider or env.get("SOC_LLM_PROVIDER") or "nvidia").strip().lower()
    common = dict(
        max_tokens=_int("SOC_MAX_TOKENS", 4096, 256, 16384),
        max_iterations=_int("SOC_MAX_ITERATIONS", 9, 2, 30),
        investigation_max_iterations=_int("SOC_INVESTIGATION_MAX_ITERATIONS", 20, 4, 60),
        assessment_max_iterations=_int("SOC_ASSESSMENT_MAX_ITERATIONS", 28, 6, 80),
        report_max_iterations=_int("SOC_REPORT_MAX_ITERATIONS", 16, 4, 60),
        assessment_max_tokens=_int("SOC_ASSESSMENT_MAX_TOKENS", 8192, 1024, 32768),
        tool_timeout_s=_float("SOC_TOOL_TIMEOUT_S", 5.0, 0.05, 120.0),
        api_max_retries=_int("SOC_API_MAX_RETRIES", 6, 1, 12),
        hermes_home=_path("SOC_HERMES_HOME", PROJECT_ROOT / ".hermes"),
        runs_dir=_path("SOC_RUNS_DIR", PROJECT_ROOT / "runs"),
        data_dir=_path("SOC_DATA_DIR", PROJECT_ROOT / "data"),
        db_path=_path("SOC_DB_PATH", PROJECT_ROOT / "state" / "soc.db"),
        reports_dir=_path("SOC_REPORTS_DIR", PROJECT_ROOT / "reports"),
        faults=parse_faults(env.get("SOC_FAULTS", "")),
    )
    if provider == "mock":
        return Settings("mock", base_url="", api_key="mock-no-key", model=MOCK_MODEL, **common)
    if provider == "nvidia":
        key = env.get("NVIDIA_API_KEY", "").strip()
        if not key:
            raise ConfigError("NVIDIA_API_KEY is not set. Put it in .env (copy .env.example), "
                              "or run with --provider mock for the offline demo (not an AI model).")
        return Settings("nvidia",
                        base_url=(env.get("NVIDIA_BASE_URL", "").strip() or NVIDIA_DEFAULT_BASE_URL).rstrip("/"),
                        api_key=key, model=env.get("NVIDIA_MODEL", "").strip() or NVIDIA_DEFAULT_MODEL, **common)
    raise ConfigError(f"Unknown SOC_LLM_PROVIDER {provider!r}. Use one of: {', '.join(PROVIDERS)}.")
