"""Adversarial review of the squash export (stage 5r): things that must never reach the
export directory, and places the source repository must never be written to."""

from __future__ import annotations

import getpass
import re
import socket
from pathlib import Path

from typer.testing import CliRunner

from go_public.cli import app

from ..conftest import git
from .test_export import AUTHOR, _basic_repo, _config, _export

runner = CliRunner()

_REFLOG_LINE = re.compile(r"^[0-9a-f]{40} [0-9a-f]{40} Pub Lic <pub@example\.com> \d+ \+0000(\t.*)?$")


def _plain_files_outside_objects(out: Path) -> list[Path]:
    return [
        p
        for p in (out / ".git").rglob("*")
        if p.is_file() and "objects" not in p.relative_to(out / ".git").parts
    ]


def test_reflog_records_only_the_export_identity(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    code, output, out = _export(tmp_path, repo)

    assert code == 0, output
    logs = [p for p in _plain_files_outside_objects(out) if "logs" in p.parts]
    for log in logs:
        for line in log.read_text().splitlines():
            assert _REFLOG_LINE.match(line), f"{log.name}: {line!r}"


def test_nothing_outside_the_object_store_names_the_local_user_or_host(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    code, output, out = _export(tmp_path, repo, "--no-set-identity")

    assert code == 0, output
    user = getpass.getuser().encode()
    host = socket.gethostname().encode()
    for path in _plain_files_outside_objects(out):
        raw = path.read_bytes()
        assert user not in raw, path
        assert host not in raw, path


def test_out_inside_the_working_tree_is_refused_when_the_source_is_a_subdirectory(
    tmp_path: Path,
) -> None:
    repo = _basic_repo(tmp_path)
    sub = repo / "src"

    code, output, out = _export(tmp_path, sub, "--out", str(repo / "public-export"))

    assert code == 2, output
    assert "outside the source repository" in output
    assert not (repo / "public-export").exists()
    assert git(repo, "status", "--porcelain").decode() == ""


def test_out_inside_the_common_git_dir_of_a_linked_worktree_is_refused(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-q", "-b", "other", str(linked))

    code, output, _out = _export(tmp_path, linked, "--out", str(repo / ".git" / "inside"))

    assert code == 2, output
    assert not (repo / ".git" / "inside").exists()


def test_report_dir_inside_the_source_is_refused_and_nothing_is_written(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)
    out = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "export",
            str(repo),
            "--out",
            str(out),
            "--author",
            AUTHOR,
            "--config",
            str(_config(tmp_path)),
            "--report-dir",
            str(repo / "reports"),
        ],
    )

    assert result.exit_code == 2, result.output
    assert not (repo / "reports").exists()
    assert not out.exists()
    assert git(repo, "status", "--porcelain").decode() == ""


def test_scan_of_a_subdirectory_refuses_a_report_dir_elsewhere_in_the_working_tree(
    tmp_path: Path,
) -> None:
    repo = _basic_repo(tmp_path)

    result = runner.invoke(
        app,
        [
            "scan",
            str(repo / "src"),
            "--config",
            str(_config(tmp_path)),
            "--report-dir",
            str(repo / "reports"),
        ],
    )

    assert result.exit_code == 2, result.output
    assert not (repo / "reports").exists()


def test_unsafe_tree_paths_are_dropped_from_the_selection() -> None:
    from go_public.config import Config
    from go_public.export.squash import Entry, select_entries

    entries = [
        Entry(b"100644", "1" * 40, path)
        for path in (
            b"sub/.GIT/hooks/post-checkout",
            b".git/config",
            b"a/../b",
            b"ok/file.txt",
        )
    ]

    selection = select_entries(entries, Config(), auto_exclude=True)

    assert [e.text for e in selection.kept] == ["ok/file.txt"]
    assert {d.reason for d in selection.dropped} == {"unsafe path"}
