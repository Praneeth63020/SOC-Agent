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
  - Hermes's registry is process-global, so every phase's tools live in toolset
    "soc". build_agent narrows the agent to the tools of ITS phase (agent.tools is
    what the model is sent, agent.valid_tool_names what Hermes will dispatch), and
    the wrapper denies any other tool via RunContext.allowed_tools as well.
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


def build_agent(settings: Settings, tools: list[ToolSpec], session_id: str, base_url: str | None = None,
                max_iterations: int | None = None) -> Any:
    """Return a Hermes AIAgent that can only call `tools` (registered under toolset 'soc')."""
    prepare_environment(settings)
    names = set(register_tools(tools))
    from run_agent import AIAgent      # imported only after HERMES_HOME is set

    agent = AIAgent(
        base_url=base_url or settings.base_url,
        api_key=settings.api_key,
        provider="custom",                  # any OpenAI-compatible endpoint (NVIDIA NIM, mock)
        model=settings.model,
        enabled_toolsets=[TOOLSET],
        max_iterations=max_iterations or settings.max_iterations,
        max_tokens=settings.max_tokens,
        tool_delay=0,
        quiet_mode=True,
        skip_memory=True,
        skip_context_files=True,
        save_trajectories=False,
        session_id=session_id,
    )
    # the toolset may also hold another phase's tools: offer and dispatch only this phase's
    agent.tools = [t for t in agent.tools or [] if (t.get("function") or {}).get("name") in names]
    agent.valid_tool_names = {n for n in agent.valid_tool_names if n in names}
    # Hermes's default of 3 retries (about 8 s of backoff) is too short for NVIDIA's free-tier rate limit (HTTP 429)
    agent._api_max_retries = settings.api_max_retries
    # Hermes's own console messages (retries, API errors with advice such as "run hermes setup", which does not
    # apply here) go to a buffer that the run record keeps, not to the user's terminal
    # (_safe_print, not _print_fn: a custom _print_fn would also switch on Hermes's animated quiet spinner)
    agent.console_lines = []
    agent._safe_print = lambda *a, **k: agent.console_lines.append(" ".join(str(x) for x in a)[:2000])
    return agent


def console_text(agent: Any, limit: int = 20_000) -> str | None:
    """What Hermes printed during the run (kept in the run record under hermes.console)."""
    lines = getattr(agent, "console_lines", None)
    return "\n".join(lines)[-limit:] if lines else None


def exposed_tool_names(agent: Any) -> list[str]:
    """Names of the tools Hermes actually offers to the model (OpenAI-format agent.tools)."""
    names = []
    for t in getattr(agent, "tools", None) or []:
        fn = t.get("function", t) if isinstance(t, dict) else {}
        if fn.get("name"):
            names.append(fn["name"])
    return sorted(names)
