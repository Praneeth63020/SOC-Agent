"""Readable explanations for common setup and runtime problems (Day 5).

The CLI and the API show `hint_for(error)` next to the raw error of a failed phase; the full error (and the
whole conversation) stays in the audit trail. No secret is ever part of a hint.
"""
from __future__ import annotations

import re
import sys

SUPPORTED_PYTHON = ((3, 11), (3, 13))           # inclusive; matches pyproject.toml requires-python

# (pattern on the error text, hint) - first match wins
_HINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"HTTP 40[13]\b|Authorization failed|Unauthorized|invalid api key", re.I),
     "The LLM API rejected the key (HTTP 401/403). Check NVIDIA_API_KEY in .env (it starts with nvapi- and must be "
     "active on build.nvidia.com), or run offline with --provider mock."),
    (re.compile(r"HTTP 404\b|model .* not found|404 page not found", re.I),
     "Model or endpoint not found (HTTP 404). Check NVIDIA_MODEL (a model with tool calling enabled on NVIDIA NIM, "
     "default nvidia/nemotron-3.5-lightning-30b-a3b) and NVIDIA_BASE_URL (default "
     "https://integrate.api.nvidia.com/v1)."),
    (re.compile(r"HTTP 429\b|rate limit|too many requests", re.I),
     "Rate limited by the LLM API (HTTP 429). Wait a minute and run again; free NVIDIA keys allow few requests per "
     "minute. --provider mock works offline."),
    (re.compile(r"HTTP 5\d\d\b|Service Unavailable|Bad Gateway|Internal Server Error", re.I),
     "The LLM service returned a server error (HTTP 5xx). Try again later, or use --provider mock."),
    (re.compile(r"Connection error|ConnectError|Name or service not known|nodename nor servname|"
                r"Temporary failure in name resolution|Network is unreachable|Connection refused|ConnectTimeout|"
                r"getaddrinfo", re.I),
     "The LLM API could not be reached (network). Check the internet connection, a proxy (HTTPS_PROXY) and "
     "NVIDIA_BASE_URL, or run offline with --provider mock."),
    (re.compile(r"Read ?timed out|ReadTimeout|timed out waiting", re.I),
     "The LLM API did not answer in time. Try again; if it keeps happening use --provider mock."),
    (re.compile(r"database is locked|database table is locked", re.I),
     "The SQLite database is locked by another soc_agent process (or a DB browser). Wait for it to finish or close "
     "it, then run again. SOC_DB_PATH can point to a different file."),
    (re.compile(r"older schema", re.I),
     "The database was created by an older version. Move it aside (state/ is git-ignored) or set SOC_DB_PATH to a "
     "new file."),
    (re.compile(r"unable to open database file|readonly database|attempt to write a readonly", re.I),
     "The SQLite database cannot be opened for writing. Check that the folder of SOC_DB_PATH exists and is "
     "writable."),
]


def hint_for(error: str | None) -> str | None:
    """A one-sentence, actionable explanation of a known error, or None."""
    if not error:
        return None
    for pat, hint in _HINTS:
        if pat.search(str(error)):
            return hint
    return None


def python_problem(version: tuple[int, int] | None = None) -> str | None:
    """Why this Python cannot run the project (None = supported)."""
    v = version or sys.version_info[:2]
    lo, hi = SUPPORTED_PYTHON
    if lo <= tuple(v) <= hi:
        return None
    return (f"Python {v[0]}.{v[1]} is not supported: use Python {lo[0]}.{lo[1]}-{hi[0]}.{hi[1]} (hermes-agent 0.19 "
            "needs it). Create the venv with e.g. `python3.11 -m venv .venv` (uv: `uv python install 3.11`).")
