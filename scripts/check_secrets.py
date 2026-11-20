"""Fail if an API key / token appears in the repository, or if .env could be committed.

    python scripts/check_secrets.py      (run before committing; CI runs it too)

Checks:
  - NVIDIA keys (nvapi-...) and other well-known key formats in any text file
  - generic key assignments: api_key = "....", TOKEN=...., password: "...."
  - .env is listed in .gitignore, is ignored by git, and is not tracked
A line can opt out with the marker  secret-scan: ignore  (use sparingly).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = [
    ("NVIDIA API key", re.compile(r"\bnvapi-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("quoted key assignment", re.compile(
        r"""(?i)\b\w*(api[_-]?key|secret|token|passw(or)?d)\w*["']?\s*[:=]\s*["'][^"'\s]{12,}["']""")),
    ("env-style key assignment", re.compile(
        r"""^\s*(export\s+)?[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Za-z0-9_]*\s*=\s*[A-Za-z0-9_\-+/=.]{12,}\s*$""",
        re.IGNORECASE)),
]
SKIP_DIRS = {".git", ".venv", "venv", ".hermes", "runs", "__pycache__", ".pytest_cache", "node_modules",
             "build", "dist", "reports"}
TEXT_SUFFIXES = {".py", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".md", ".txt", ".cfg", ".ini", ".log",
                 ".sh", ".csv", ".example", ".env"}


def _is_text_candidate(path: Path) -> bool:
    return path.suffix in TEXT_SUFFIXES or path.name.startswith(".env")


def scan(root: Path) -> list[tuple[str, int, str]]:
    """[(file, line number, finding)] for every suspected secret under root (.env itself excluded)."""
    found = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if not path.is_file() or any(p in SKIP_DIRS or p.endswith(".egg-info") for p in rel.parts[:-1]):
            continue
        if path.name == ".env" or not _is_text_candidate(path):
            continue        # .env is allowed to hold the real key locally; it must never be committed
        for i, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if "secret-scan: ignore" in line:
                continue
            for label, pat in PATTERNS:
                if pat.search(line):
                    found.append((str(rel), i, label))
                    break
    return found


def git_problems(root: Path) -> list[str]:
    problems = []
    if ".env" not in (root / ".gitignore").read_text(encoding="utf-8").splitlines():
        problems.append(".env is not listed in .gitignore")
    try:
        tracked = subprocess.run(["git", "ls-files", "--", ".env", "*/.env"], cwd=root,
                                 capture_output=True, text=True)
        ignored = subprocess.run(["git", "check-ignore", "-q", ".env"], cwd=root)
    except FileNotFoundError:
        return problems                      # git not installed: .gitignore check only
    if tracked.returncode == 0 and tracked.stdout.strip():
        problems.append(f".env is tracked by git ({tracked.stdout.split()}) - `git rm --cached` it and "
                        "rotate the key")
    if ignored.returncode == 1:
        problems.append(".env is not ignored by git")
    return problems


def main() -> int:
    problems = [f"possible secret ({label}) in {f}:{n}" for f, n, label in scan(ROOT)] + git_problems(ROOT)
    for p in problems:
        print(p)
    print("Secret check:", "OK" if not problems else f"FAILED - {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
