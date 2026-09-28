"""End-to-end CLI checks: exit codes and the printed inventory line."""

from __future__ import annotations

import json
import random
from pathlib import Path

from typer.testing import CliRunner

from go_public import __version__
from go_public.cli import app

from ..conftest import commit_file, init_repo
from ..unit import secret_tokens as tok

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
        app, ["fixture", "--seed", "0", "--size", "medium", "--out", str(tmp_path / "fixture")]
    )
    assert result.exit_code == 2


def test_fixture_small_size_builds_a_repo(tmp_path: Path) -> None:
    out = tmp_path / "fixture"
    result = runner.invoke(app, ["fixture", "--seed", "0", "--size", "small", "--out", str(out)])
    assert result.exit_code == 0
    assert (out / "repo").is_dir()
    assert (out / "truth.jsonl").is_file()


def test_rules_check_prints_bundled_summary() -> None:
    result = runner.invoke(app, ["rules", "check"])
    assert result.exit_code == 0
    assert "222 rules: 221 content regexes, 1 path-only; 49 allowlist regexes compiled" in (
        result.stdout
    )


def test_rules_check_unknown_key_exits_2(tmp_path: Path) -> None:
    bad_config = tmp_path / "bad.toml"
    bad_config.write_text('title = "x"\nbogus = true\n')
    result = runner.invoke(app, ["rules", "check", "--gitleaks-config", str(bad_config)])
    assert result.exit_code == 2


def test_rules_check_reports_compile_failures_exit_1(tmp_path: Path) -> None:
    bad_config = tmp_path / "bad.toml"
    bad_config.write_text('[[rules]]\nid = "r1"\npath = "ok"\nregex = "(unclosed"\n')
    result = runner.invoke(app, ["rules", "check", "--gitleaks-config", str(bad_config)])
    assert result.exit_code == 1
    assert "failed to compile" in result.stdout


def test_scan_with_no_secrets_exits_0_with_zero_findings(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 0
    assert "0 finding(s)" in result.stdout


def test_scan_with_a_secret_exits_1_by_default(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.aws_access_key(random.Random(42))
    commit_file(repo, "config.txt", f'access_key = "{token}"\n', "feat: add config")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 1
    assert "1 finding(s)" in result.stdout
    assert "secret=1" in result.stdout
    assert "critical=1" in result.stdout
    assert token not in result.stdout


def test_scan_fail_on_critical_only_lets_high_through(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    # generic-entropy findings are severity "high", not "critical".
    value = tok.generic_high_entropy_value(random.Random(43))
    commit_file(repo, "config.txt", f'password = "{value}"\n', "feat: add password")
    result = runner.invoke(app, ["scan", str(repo), "--fail-on", "critical"])
    assert result.exit_code == 0
    assert "critical=" not in result.stdout
    assert "high=" in result.stdout


def test_scan_unknown_fail_on_exits_2(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    result = runner.invoke(app, ["scan", str(repo), "--fail-on", "bogus"])
    assert result.exit_code == 2


def test_scan_jobs_flag_still_finds_the_secret(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.stripe_secret_key(random.Random(44))
    commit_file(repo, "config.txt", f'key = "{token}"\n', "feat: add key")
    result = runner.invoke(app, ["scan", str(repo), "--jobs", "2"])
    assert result.exit_code == 1
    assert "secret=1" in result.stdout


def test_scan_debug_json_writes_findings(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.npm_token(random.Random(45))
    commit_file(repo, "config.txt", f'token = "{token}"\n', "feat: add token")
    debug_json = tmp_path / "debug.json"
    result = runner.invoke(app, ["scan", str(repo), "--debug-json", str(debug_json)])
    assert result.exit_code == 1
    findings = json.loads(debug_json.read_text())
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "npm-access-token"
    assert token not in debug_json.read_text()
