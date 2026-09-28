"""Static source checks: no `push`, and no `subprocess` outside the allowed modules.

These are the tests architecture.md calls for under "Git runner": nothing in the
package may invoke git with `push`, and nothing outside the git runner (plus, in
later stages, `export/history.py` and `bench/`) may shell out at all.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "go_public"

# The runner's own forbidden-subcommand set legitimately names "push" as a string;
# nowhere else may even mention it as a git invocation.
_PUSH_ALLOWED_FILES = {"git/runner.py"}
_PUSH_RE = re.compile(r"""["']push["']""")

# Modules allowed to shell out. Only `git/runner.py` exists in stage 1a; later
# stages add `export/history.py` (git-filter-repo child process) and `bench/`
# (the clone-only runner for `--real-world-dir`).
_SUBPROCESS_ALLOWED_FILES = {"git/runner.py"}
_SUBPROCESS_ALLOWED_DIRS = ("export/", "bench/")
_SUBPROCESS_CALL_RE = re.compile(r"subprocess\.(run|Popen|call|check_call|check_output)\(")


def _all_source_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def test_no_git_push_invocation() -> None:
    offenders = []
    for path in _all_source_files():
        rel = path.relative_to(SRC).as_posix()
        if rel in _PUSH_ALLOWED_FILES:
            continue
        if _PUSH_RE.search(path.read_text()):
            offenders.append(rel)
    assert offenders == []


def test_subprocess_only_used_in_allowed_modules() -> None:
    offenders = []
    for path in _all_source_files():
        rel = path.relative_to(SRC).as_posix()
        if rel in _SUBPROCESS_ALLOWED_FILES or rel.startswith(_SUBPROCESS_ALLOWED_DIRS):
            continue
        if _SUBPROCESS_CALL_RE.search(path.read_text()):
            offenders.append(rel)
    assert offenders == []
