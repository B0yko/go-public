"""Adversarial cases for the squash export: things that must never reach the
export directory, and places the source repository must never be written to."""

from __future__ import annotations

import getpass
import os
import re
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from go_public.cli import app

from ..conftest import git
from .test_export import AUTHOR, REG, _basic_repo, _config, _export

runner = CliRunner()

_REFLOG_LINE = re.compile(
    r"^[0-9a-f]{40} [0-9a-f]{40} Pub Lic <pub@example\.com> \d+ \+0000(\t.*)?$"
)


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


def test_precheck_does_not_count_on_strip_for_formats_strip_leaves_alone(tmp_path: Path) -> None:
    from PIL.ExifTags import Base as ExifTag

    from go_public.bench import binaries

    tiff = binaries.tiff_with_field(ExifTag.Artist.value, "Zed Secretperson")
    repo = _basic_repo(tmp_path, [(REG, "scan/page.tiff", tiff)])

    code, output, out = _export(tmp_path, repo, "--fail-on", "medium")

    assert code == 1
    assert "exif-person" in output
    assert "scan/page.tiff" in output
    assert not out.exists()


def test_precheck_still_lets_strip_resolve_jpeg_person_fields(tmp_path: Path) -> None:
    from PIL.ExifTags import Base as ExifTag

    from go_public.bench import binaries

    jpeg = binaries.jpeg_with_field(ExifTag.Artist.value, "Zed Secretperson")
    repo = _basic_repo(tmp_path, [(REG, "img/photo.jpg", jpeg)])

    code, output, out = _export(tmp_path, repo, "--fail-on", "medium")

    assert code == 0, output
    assert b"Zed Secretperson" not in (out / "img" / "photo.jpg").read_bytes()


def test_symlink_and_case_variant_directory_never_write_outside_out(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    repo = _basic_repo(
        tmp_path,
        [
            ("120000", "dir", str(outside).encode()),
            (REG, "DIR/pwned.txt", b"written through a symlink\n"),
        ],
    )

    _code, _output, out = _export(tmp_path, repo)

    assert list(outside.iterdir()) == []
    assert out.exists()


def _repo_with_evil_filter(tmp_path: Path) -> tuple[Path, Path]:
    marker = tmp_path / "filter-ran"
    repo = _basic_repo(tmp_path)
    (repo / ".gitattributes").write_text("* filter=evil\n")
    git(repo, "add", ".gitattributes")
    git(repo, "commit", "-qm", "attrs")
    git(repo, "config", "filter.evil.clean", f"sh -c 'touch {marker}; cat'")
    git(repo, "config", "filter.evil.smudge", "cat")
    git(repo, "config", "filter.evil.required", "true")
    git(repo, "config", "core.fsmonitor", f"touch {marker}")
    # make every tracked file look modified to git's stat check
    for path in repo.rglob("*"):
        if path.is_file() and ".git" not in path.parts:
            path.write_bytes(path.read_bytes())
    marker.unlink(missing_ok=True)
    return repo, marker


def test_scan_never_runs_filter_drivers_from_the_repository_config(tmp_path: Path) -> None:
    repo, marker = _repo_with_evil_filter(tmp_path)

    runner.invoke(
        app,
        [
            "scan",
            str(repo),
            "--config",
            str(_config(tmp_path)),
            "--report-dir",
            str(tmp_path / "r"),
        ],
    )

    assert not marker.exists()


def test_export_never_runs_filter_drivers_from_the_repository_config(tmp_path: Path) -> None:
    repo, marker = _repo_with_evil_filter(tmp_path)

    _export(tmp_path, repo)

    assert not marker.exists()


def test_hostile_user_git_environment_leaves_no_trace_in_the_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hooks = tmp_path / "user-hooks"
    template = tmp_path / "user-template"
    (template / "hooks").mkdir(parents=True)
    (template / "hooks" / "post-checkout").write_text("#!/bin/sh\ntouch hook-ran\n")
    (template / "info").mkdir()
    (template / "description").write_text("user template description\n")
    hooks.mkdir()
    (hooks / "post-checkout").write_text("#!/bin/sh\ntouch hook-ran\n")
    (hooks / "post-checkout").chmod(0o755)
    (template / "hooks" / "post-checkout").chmod(0o755)
    home = Path(os.environ["HOME"])
    user_config = (
        "[user]\n\tname = Somebody Else\n\temail = else@example.com\n"
        f"[init]\n\ttemplateDir = {template}\n"
        f"[core]\n\thooksPath = {hooks}\n"
        "[commit]\n\tgpgsign = true\n"
        '[remote "origin"]\n\turl = https://example.invalid/x.git\n'
    )
    (home / ".gitconfig").write_text(user_config)
    (home / ".config" / "git").mkdir(parents=True, exist_ok=True)
    (home / ".config" / "git" / "config").write_text(user_config)
    repo = _basic_repo(tmp_path)
    hostile_env = {
        "GIT_AUTHOR_NAME": "Env Author",
        "GIT_AUTHOR_EMAIL": "env-author@example.com",
        "GIT_COMMITTER_NAME": "Env Committer",
        "GIT_COMMITTER_EMAIL": "env-committer@example.com",
        "GIT_TEMPLATE_DIR": str(template),
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": str(hooks),
        "GIT_DIR": str(tmp_path / "nowhere"),
        "GIT_WORK_TREE": str(tmp_path / "nowhere"),
        "EMAIL": "env-email@example.com",
    }
    for name, value in hostile_env.items():
        monkeypatch.setenv(name, value)

    code, output, out = _export(tmp_path, repo)

    for name in hostile_env:
        monkeypatch.delenv(name)
    assert code == 0, output
    assert not (out / "hook-ran").exists()
    assert not list((out / ".git" / "hooks").glob("*"))
    config = (out / ".git" / "config").read_text()
    for needle in ("hooksPath", "templateDir", "Somebody", "else@example", "invalid", "origin"):
        assert needle not in config
    assert not (out / ".git" / "description").exists()
    raw = git(out, "cat-file", "-p", "HEAD").decode()
    assert "Pub Lic <pub@example.com>" in raw
    for needle in ("Env ", "env-", "Somebody", "else@example"):
        assert needle not in raw
    for log in (out / ".git" / "logs").rglob("*"):
        if log.is_file():
            assert "Env " not in log.read_text() and "env-" not in log.read_text()
