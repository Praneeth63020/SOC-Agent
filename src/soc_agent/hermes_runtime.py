"""Creates locked-down Hermes agents.

Least privilege, enforced by configuration rather than by prompt:
  - enabled_toolsets=["soc"]: the model is only offered our tools; Hermes's
    built-in tools (terminal, browser, file, web, memory, skills, ...) are never
    sent to the model, and calls to them are refused by Hermes
    ("Tool 'x' does not exist").
  - skip_memory / skip_context_files: no persistent memory, and no AGENTS.md /
    context files from the working directory are injected.
  - HERMES_HOME points to a project-local, git-ignored folder (set BEFORE Hermes
    is imported), so the user's personal ~/.hermes config, keys and sessions are
    never read or modified.
  - max_iterations caps tool-calling rounds per task (step limit).
"""
from __future__ import annotations

import os
from typing import Any

from soc_agent.config import Settings
from soc_agent.tools.base import TOOLSET, ToolSpec, register_tools

LOCAL_HOSTS = ("127.0.0.1", "localhost")


def prepare_environment(settings: Settings) -> None:
    settings.hermes_home.mkdir(parents=True, exist_ok=True)
    os.environ["HERMES_HOME"] = str(settings.hermes_home)
    # the in-process mock server must never be reached through a system proxy
    for var in ("NO_PROXY", "no_proxy"):
        parts = [p for p in os.environ.get(var, "").split(",") if p]
        os.environ[var] = ",".join(parts + [h for h in LOCAL_HOSTS if h not in parts])


def build_agent(settings: Settings, tools: list[ToolSpec], session_id: str, base_url: str | None = None) -> Any:
    """Return a Hermes AIAgent that can only call `tools` (registered under toolset 'soc')."""
    prepare_environment(settings)
    register_tools(tools)
    from run_agent import AIAgent      # imported only after HERMES_HOME is set

    return AIAgent(
        base_url=base_url or settings.base_url,
        api_key=settings.api_key,
        provider="custom",                  # any OpenAI-compatible endpoint (NVIDIA NIM, mock)
        model=settings.model,
        enabled_toolsets=[TOOLSET],
        max_iterations=settings.max_iterations,
        max_tokens=settings.max_tokens,
        tool_delay=0,
        quiet_mode=True,
        skip_memory=True,
        skip_context_files=True,
        save_trajectories=False,
        session_id=session_id,
    )


def exposed_tool_names(agent: Any) -> list[str]:
    """Names of the tools Hermes actually offers to the model (OpenAI-format agent.tools)."""
    names = []
    for t in getattr(agent, "tools", None) or []:
        fn = t.get("function", t) if isinstance(t, dict) else {}
        if fn.get("name"):
            names.append(fn["name"])
    return sorted(names)
