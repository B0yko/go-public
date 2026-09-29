"""`bench/gitleaks.py`: command lines, mapping gitleaks findings back to blob and line,
the checkout, and the plumbing around a (fake) gitleaks binary."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from go_public.bench import gitleaks as gl
from go_public.bench import run as bench_run
from go_public.git.runner import GitRunner

from ..conftest import commit_file, git, hash_blob, init_repo


def _fake_binary(tmp_path: Path, version: str = "8.30.1", report: object = ()) -> Path:
    """A shell script that answers `version` and writes `report` to `--report-path`."""
    script = tmp_path / "fake-gitleaks"
    script.write_text(
        "#!/bin/sh\n"
        f'if [ "$1" = version ]; then echo {version}; exit 0; fi\n'
        "while [ $# -gt 0 ]; do\n"
        '  if [ "$1" = "--report-path" ]; then out="$2"; fi\n'
        "  shift\n"
        "done\n"
        f"cat > \"$out\" <<'JSON'\n{json.dumps(report)}\nJSON\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def test_command_lines_record_the_options_and_hide_paths() -> None:
    git_cmd = gl.command_line("git")
    assert git_cmd.startswith("gitleaks git --log-opts=--all ")
    assert "<target>" in git_cmd and "<report>" in git_cmd
    assert gl.command_line("git_no_replace").startswith("GIT_NO_REPLACE_OBJECTS=1 gitleaks git")
    assert gl.command_line("dir", "--max-archive-depth", "2").startswith("gitleaks dir ")
    assert "--max-archive-depth 2" in gl.command_line("dir", "--max-archive-depth", "2")


def test_every_location_type_of_a_secret_plant_has_a_row() -> None:
    from go_public.bench.plants import LOCATION_TYPES

    named = {name for name, _why in gl.LOCATIONS}
    assert {"head", "history_only", "unreachable", "commit_message", "tag_message"} <= named
    assert named <= set(LOCATION_TYPES)


def test_version_is_read_and_checked(tmp_path: Path) -> None:
    assert gl.gitleaks_version(_fake_binary(tmp_path)) == "8.30.1"


def test_run_gitleaks_reads_the_report_and_times_it(tmp_path: Path) -> None:
    findings = [{"RuleID": "r", "File": "a.txt", "StartLine": 3, "Commit": "c"}]
    binary = _fake_binary(tmp_path, report=findings)
    home = tmp_path / "home"
    home.mkdir()
    result = gl.run_gitleaks(binary, "git", tmp_path, home)
    assert result.findings == findings
    assert result.wall_s >= 0
    empty = gl.run_gitleaks(_fake_binary(tmp_path, report=[]), "dir", tmp_path, home)
    assert empty.findings == []


def _repo_with_history(tmp_path: Path) -> tuple[Path, str, str]:
    repo = init_repo(tmp_path / "repo")
    first = commit_file(repo, "a.txt", "one\ntwo\n", "add a")
    commit_file(repo, "a.txt", "one\ntwo\nthree\n", "extend a")
    return repo, first, git(repo, "rev-parse", "HEAD:a.txt").decode().strip()


def test_keys_from_git_resolve_the_blob_at_the_reporting_commit(tmp_path: Path) -> None:
    repo, first, _head_blob = _repo_with_history(tmp_path)
    old_blob = git(repo, "rev-parse", f"{first}:a.txt").decode().strip()
    runner = GitRunner(repo, role="source")
    findings = [
        {"File": "a.txt", "StartLine": 2, "Commit": first},
        {"File": "a.txt", "StartLine": 0, "Commit": first},  # path-only rule: no line
        {"File": "gone.txt", "StartLine": 1, "Commit": first},  # unresolvable
        {"File": "a.zip!inner.txt", "StartLine": 1, "Commit": first},  # archive member
    ]
    assert gl.keys_from_git(runner, findings) == {(old_blob, 2)}
    assert gl.keys_from_git_any_line(runner, [findings[3], {"File": "a.txt", "Commit": first}]) == {
        (old_blob, 0)
    }


def test_keys_from_dir_map_paths_to_head_blobs(tmp_path: Path) -> None:
    repo, _first, head_blob = _repo_with_history(tmp_path)
    checkout = gl.checkout_head(repo, tmp_path / "checkout")
    assert (checkout / "a.txt").is_file()
    assert not (checkout / ".git").exists()
    runner = GitRunner(repo, role="source")
    findings = [
        {"File": str(checkout / "a.txt"), "StartLine": 3},
        {"File": str(tmp_path / "elsewhere" / "a.txt"), "StartLine": 1},
    ]
    assert gl.keys_from_dir(runner, checkout, findings) == {(head_blob, 3)}


def test_blobs_for_handles_unknown_specs(tmp_path: Path) -> None:
    repo, first, _ = _repo_with_history(tmp_path)
    runner = GitRunner(repo, role="source")
    unknown = hash_blob(repo, "dangling\n")
    assert gl._blobs_for(runner, []) == {}
    resolved = gl._blobs_for(runner, [f"{first}:a.txt", f"{first}:nope", f"{unknown}:x"])
    assert set(resolved) == {f"{first}:a.txt"}


def test_a_wrong_gitleaks_version_is_refused(tmp_path: Path) -> None:
    options = bench_run.BenchOptions(seed_spec="0", size="tiny", out=tmp_path / "out")
    with bench_run.Workspace(options) as workspace, pytest.raises(gl.GitleaksError):
        gl.run_gitleaks_baseline(workspace, _fake_binary(tmp_path, version="8.0.0"))


REAL_BINARY = os.environ.get("GO_PUBLIC_TEST_GITLEAKS")


@pytest.mark.skipif(
    not REAL_BINARY, reason="set GO_PUBLIC_TEST_GITLEAKS to a gitleaks 8.30.1 binary"
)
def test_baseline_on_the_tiny_fixture_with_the_real_binary(tmp_path: Path) -> None:
    options = bench_run.BenchOptions(seed_spec="0", size="tiny", out=tmp_path / "out")
    with bench_run.Workspace(options) as workspace:
        data, md = gl.run_gitleaks_baseline(workspace, Path(str(REAL_BINARY)))
    summary = data["summary"]
    assert summary["go_public"]["found"] == summary["expected"]
    assert summary["dir"]["found"] <= summary["git"]["found"] <= summary["expected"]
    assert "outside scope" in md
