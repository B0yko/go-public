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


def test_failing_worker_initializer_raises_instead_of_hanging(tmp_path: Path) -> None:
    """Run in a child process with a hard timeout: a regression must fail this test,
    not hang the suite."""
    repo = _two_file_repo(tmp_path)
    program = textwrap.dedent(
        f"""
        from pathlib import Path
        from go_public import scan
        from go_public.errors import ScanWorkerError
        from go_public.git.inventory import build
        from go_public.git.runner import GitRunner


        def failing(runner, options):
            raise RuntimeError("worker bootstrap failed")


        if __name__ == "__main__":
            scan._pool_init = failing
            runner = GitRunner(Path({str(repo)!r}), role="source")
            try:
                scan.run(runner, build(runner), scan.ScanOptions(jobs=2))
            except ScanWorkerError as exc:
                print("failed cleanly:", exc)
                raise SystemExit(0)
            raise SystemExit("scan finished although every worker failed")
        """
    )
    script = tmp_path / "pool_failure.py"
    script.write_text(program)
    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, timeout=60, cwd=tmp_path
    )
    assert proc.returncode == 0, proc.stderr
    assert "--jobs 1" in proc.stdout
    assert time.monotonic() - started < 45


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
