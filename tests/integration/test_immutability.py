"""The source repository is never modified by a go-public command.

Product spec item 17: fingerprint every ref, `count-objects -v`, a hash of
`.git/config`, `HEAD`, the index, and `git --no-optional-locks status --porcelain`,
before and after running a command, and assert it is unchanged. Covers `scan`, `show`
and the squash export, on a working-tree repository and on a bare one; the
history-preserving export extends it when it lands.
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from go_public.cli import app
from go_public.git.inventory import build, build_head_only
from go_public.git.runner import GitRunner

from ..conftest import commit_entries, commit_file, git, init_repo

runner = CliRunner()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "absent"


def _git_dir(repo: Path) -> Path:
    return repo / ".git" if (repo / ".git").exists() else repo


def _fingerprint(repo: Path) -> dict[str, object]:
    git_dir = _git_dir(repo)
    bare = git_dir == repo
    return {
        "refs": git(repo, "for-each-ref", "--format=%(refname) %(objectname)"),
        "count": git(repo, "count-objects", "-v"),
        "config": _sha(git_dir / "config"),
        "head_file": _sha(git_dir / "HEAD"),
        "head": git(repo, "rev-parse", "HEAD"),
        "index": _sha(git_dir / "index"),
        "index_mtime": None if bare else (git_dir / "index").stat().st_mtime_ns,
        "status": b"" if bare else git(repo, "--no-optional-locks", "status", "--porcelain"),
        "packed_refs": _sha(git_dir / "packed-refs"),
        "hooks": sorted(p.name for p in (git_dir / "hooks").glob("*")),
        "objects": sorted(
            p.relative_to(git_dir).as_posix()
            for p in (git_dir / "objects").rglob("*")
            if p.is_file()
        ),
    }


def _config_file(tmp_path: Path) -> Path:
    path = tmp_path / "go-public.toml"
    path.write_text('[identity]\nallow = ["Pat Public <pat@example.com>"]\n[scan]\njobs = 1\n')
    return path


def _populated(tmp_path: Path, *, bare: bool = False) -> Path:
    repo = init_repo(tmp_path / ("src.git" if bare else "src"), bare=bare)
    if bare:
        commit_entries(repo, [("100644", "a.txt", b"hi\n"), ("100644", "b.txt", b"hi2\n")])
    else:
        commit_file(repo, "a.txt", "hi\n", "feat: a")
        commit_file(repo, "b.txt", "hi2\n", "feat: b", date="2024-01-02T00:00:00+00:00")
    git(repo, "tag", "-a", "v1.0", "-m", "release", "HEAD")
    return repo


def test_scan_does_not_modify_the_source_repo(tmp_path: Path) -> None:
    repo = _populated(tmp_path)

    before = _fingerprint(repo)
    time.sleep(0.01)
    gr = GitRunner(repo, role="source")
    build(gr, include_unreachable=True)
    build_head_only(gr)
    after = _fingerprint(repo)

    assert before == after


@pytest.mark.parametrize("bare", [False, True])
def test_cli_scan_show_and_export_leave_the_source_untouched(tmp_path: Path, bare: bool) -> None:
    repo = _populated(tmp_path, bare=bare)
    config = str(_config_file(tmp_path))
    before = _fingerprint(repo)
    time.sleep(0.01)

    scan = runner.invoke(
        app, ["scan", str(repo), "--config", config, "--report-dir", str(tmp_path / "r1")]
    )
    scan_all = runner.invoke(
        app,
        [
            "scan",
            str(repo),
            "--config",
            config,
            "--include-unreachable",
            "--report-dir",
            str(tmp_path / "r2"),
        ],
    )
    show = runner.invoke(app, ["show", str(repo), "a.txt", "--config", config])
    check = runner.invoke(app, ["export", str(repo), "--check", "--config", config])
    export = runner.invoke(
        app,
        [
            "export",
            str(repo),
            "--out",
            str(tmp_path / "out"),
            "--author",
            "Pub Lic <pub@example.com>",
            "--config",
            config,
            "--report-dir",
            str(tmp_path / "r3"),
        ],
    )

    assert scan.exit_code in (0, 1) and scan_all.exit_code in (0, 1)
    assert show.exit_code == 0
    assert check.exit_code in (0, 1)
    assert export.exit_code in (0, 1), export.output
    assert (tmp_path / "out" / ".git").is_dir()
    assert _fingerprint(repo) == before


def test_export_does_not_change_the_source_mtime_of_the_index(tmp_path: Path) -> None:
    repo = _populated(tmp_path)
    index = repo / ".git" / "index"
    stamp = os.stat(index).st_mtime_ns

    runner.invoke(
        app,
        [
            "export",
            str(repo),
            "--out",
            str(tmp_path / "out"),
            "--author",
            "Pub Lic <pub@example.com>",
            "--config",
            str(_config_file(tmp_path)),
            "--report-dir",
            str(tmp_path / "r"),
        ],
    )

    assert os.stat(index).st_mtime_ns == stamp
