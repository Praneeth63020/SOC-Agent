"""Settings from environment / .env. Secrets are only ever read from the environment."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]

NVIDIA_DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
# meta/llama-3.3-70b-instruct (named in the brief) is no longer listed on NVIDIA's API (checked 2026-11-20);
NVIDIA_DEFAULT_MODEL = "nvidia/nemotron-3.5-lightning-30b-a3b"   # verified live with tool calling
MOCK_MODEL = "mock-soc-planner"
PROVIDERS = ("nvidia", "mock")


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    llm_provider: str            # "nvidia" (real model) | "mock" (offline deterministic script)
    base_url: str                # empty for mock: filled in when the in-process server starts
    api_key: str | None
    model: str
    max_tokens: int = 4096       # a full plan is one tool call; ~1.5k tokens for the mock's 7 steps
    max_iterations: int = 6      # Hermes tool-calling iterations per task (step limit)
    hermes_home: Path = PROJECT_ROOT / ".hermes"   # isolated Hermes state, git-ignored
    runs_dir: Path = PROJECT_ROOT / "runs"         # run records (JSON), git-ignored

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


def _path(name: str, default: Path) -> Path:
    raw = os.environ.get(name, "").strip()
    p = Path(raw).expanduser() if raw else default
    return p if p.is_absolute() else PROJECT_ROOT / p


def runs_dir() -> Path:
    _load_env()
    return _path("SOC_RUNS_DIR", PROJECT_ROOT / "runs")


def load_settings(provider: str | None = None) -> Settings:
    _load_env()
    env = os.environ
    provider = (provider or env.get("SOC_LLM_PROVIDER") or "nvidia").strip().lower()
    common = dict(
        max_tokens=_int("SOC_MAX_TOKENS", 4096, 256, 16384),
        max_iterations=_int("SOC_MAX_ITERATIONS", 6, 2, 30),
        hermes_home=_path("SOC_HERMES_HOME", PROJECT_ROOT / ".hermes"),
        runs_dir=_path("SOC_RUNS_DIR", PROJECT_ROOT / "runs"),
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
