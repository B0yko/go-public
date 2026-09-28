"""`report/location.py`: default location, refusing to write inside the scanned
repository, permissions, and the `latest` symlink."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from go_public.errors import UsageError
from go_public.report.location import (
    default_report_root,
    latest_report_dir,
    prepare_report_dir,
    resolve_report_dir,
    update_latest_symlink,
)


def test_default_report_root_uses_xdg_state_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert default_report_root() == tmp_path / "state" / "go-public"


def test_resolve_report_dir_default_is_under_xdg_state_and_timestamped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scanned_repo = tmp_path / "repo"
    scanned_repo.mkdir()

    report_dir = resolve_report_dir(repo_name="myrepo", scanned_repo=scanned_repo)

    assert report_dir.parent == tmp_path / "state" / "go-public" / "myrepo"
    assert report_dir.name.endswith("Z")


def test_resolve_report_dir_refuses_inside_the_scanned_repo(tmp_path: Path) -> None:
    scanned_repo = tmp_path / "repo"
    scanned_repo.mkdir()
    inside = scanned_repo / "reports"

    with pytest.raises(UsageError):
        resolve_report_dir(repo_name="myrepo", scanned_repo=scanned_repo, override=inside)


def test_resolve_report_dir_refuses_the_scanned_repo_itself(tmp_path: Path) -> None:
    scanned_repo = tmp_path / "repo"
    scanned_repo.mkdir()

    with pytest.raises(UsageError):
        resolve_report_dir(repo_name="myrepo", scanned_repo=scanned_repo, override=scanned_repo)


def test_resolve_report_dir_allows_an_override_outside_the_repo(tmp_path: Path) -> None:
    scanned_repo = tmp_path / "repo"
    scanned_repo.mkdir()
    outside = tmp_path / "reports-elsewhere"

    result = resolve_report_dir(repo_name="myrepo", scanned_repo=scanned_repo, override=outside)

    assert result == outside.resolve()


def test_prepare_report_dir_sets_mode_0700(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b"
    prepare_report_dir(target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o700


def test_latest_symlink_points_at_the_newest_report_dir(tmp_path: Path) -> None:
    root = tmp_path / "repo-name"
    first = root / "20240101T000000Z"
    second = root / "20240102T000000Z"
    prepare_report_dir(first)
    prepare_report_dir(second)

    update_latest_symlink(first)
    update_latest_symlink(second)

    latest = root / "latest"
    assert latest.resolve() == second


def test_latest_report_dir_returns_none_when_never_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert latest_report_dir("never-scanned") is None


def test_latest_report_dir_resolves_the_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    report_dir = tmp_path / "state" / "go-public" / "myrepo" / "20240101T000000Z"
    prepare_report_dir(report_dir)
    update_latest_symlink(report_dir)

    assert latest_report_dir("myrepo") == report_dir
