"""The scan worker pool fails fast when workers cannot start; it never respawns forever."""

from __future__ import annotations

import os
import random
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from go_public import scan
from go_public.cli import app
from go_public.errors import ScanWorkerError
from go_public.git.inventory import build
from go_public.git.runner import GitRunner
from go_public.scan import ScanOptions
from tests.conftest import commit_file, init_repo
from tests.unit import secret_tokens as tok


def _failing_initializer(runner: object, options: object) -> None:
    raise RuntimeError("worker bootstrap failed")


def _two_file_repo(tmp_path: Path) -> Path:
    repo = init_repo(tmp_path / "repo")
    rng = random.Random(3)
    commit_file(repo, "a.txt", f'k = "{tok.stripe_secret_key(rng)}"\n', "feat: a")
    commit_file(repo, "b.txt", f'k = "{tok.npm_token(rng)}"\n', "feat: b")
    return repo


def test_failing_worker_initializer_raises_instead_of_hanging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _two_file_repo(tmp_path)
    runner = GitRunner(repo, role="source")
    inventory = build(runner)
    monkeypatch.setattr(scan, "_pool_init", _failing_initializer)
    started = time.monotonic()
    with pytest.raises(ScanWorkerError, match="--jobs 1"):
        scan.run(runner, inventory, ScanOptions(jobs=2))
    assert time.monotonic() - started < 30


def test_cli_maps_a_dead_pool_to_exit_3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _two_file_repo(tmp_path)
    monkeypatch.setattr(scan, "_pool_init", _failing_initializer)
    result = CliRunner().invoke(app, ["scan", str(repo), "--jobs", "2", "--quiet"])
    assert result.exit_code == 3
    assert "--jobs 1" in (result.stdout + result.stderr)


def test_scan_from_a_stdin_script_never_hangs(tmp_path: Path) -> None:
    """`python -` cannot be re-imported by spawned workers: work, or fail fast."""
    repo = _two_file_repo(tmp_path)
    program = textwrap.dedent(
        f"""
        from pathlib import Path
        from go_public import scan
        from go_public.git.inventory import build
        from go_public.git.runner import GitRunner
        runner = GitRunner(Path({str(repo)!r}), role="source")
        found = scan.run(runner, build(runner), scan.ScanOptions(jobs=2))
        print(len(found))
        """
    )
    proc = subprocess.run(
        [sys.executable, "-"],
        input=program,
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ},
    )
    assert proc.returncode == 0 or "--jobs 1" in proc.stderr
