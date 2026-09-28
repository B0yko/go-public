"""End-to-end CLI checks: exit codes and the printed inventory line."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from go_public import __version__
from go_public.cli import app

from ..conftest import commit_file, init_repo

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_scan_prints_inventory_line(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 0
    assert result.stdout.startswith("inventory: ")


def test_scan_head_only_flag(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    result = runner.invoke(app, ["scan", str(repo), "--head-only"])
    assert result.exit_code == 0
    assert "inventory: 0 refs, 0 commits" in result.stdout


def test_scan_include_unreachable_flag(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    result = runner.invoke(app, ["scan", str(repo), "--include-unreachable"])
    assert result.exit_code == 0


def test_scan_not_a_repo_exits_3(tmp_path: Path) -> None:
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    result = runner.invoke(app, ["scan", str(not_a_repo)])
    assert result.exit_code == 3


def test_scan_missing_path_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path / "does-not-exist")])
    assert result.exit_code == 2


def test_scan_sha256_repo_exits_3(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo", object_format="sha256")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 3


def test_fixture_builds_a_tiny_repo(tmp_path: Path) -> None:
    out = tmp_path / "fixture"
    result = runner.invoke(app, ["fixture", "--seed", "0", "--size", "tiny", "--out", str(out)])
    assert result.exit_code == 0
    assert (out / "repo").is_dir()
    assert (out / "truth.jsonl").is_file()
    assert (out / "go-public.toml").is_file()


def test_fixture_unsupported_size_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["fixture", "--seed", "0", "--size", "small", "--out", str(tmp_path / "fixture")]
    )
    assert result.exit_code == 2
