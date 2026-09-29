"""End-to-end CLI checks: exit codes and the printed inventory line."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from typer.testing import CliRunner

from go_public import __version__
from go_public.cli import app

from ..conftest import commit_file, git, init_repo
from ..unit import secret_tokens as tok

runner = CliRunner()


def _allow_public_identity_config(tmp_path: Path) -> Path:
    """A config allowlisting `conftest.PUBLIC_IDENT`, so these secret-focused tests
    don't also see the identity finding every commit's author now produces by
    default (`detect/commit_meta.py`)."""
    config = tmp_path / "go-public.toml"
    config.write_text('[identity]\nallow = ["Pat Public <pat@example.com>"]\n')
    return config


def _commit_licence(repo: Path) -> None:
    """A LICENSE file, so these secret-focused tests don't also see the info-level
    `licence-missing-at-head` finding (`detect/licence.py`) every repo
    without one now produces by default."""
    commit_file(
        repo,
        "LICENSE",
        "MIT License\n\nPermission is hereby granted, free of charge, to any person "
        "obtaining a copy of this software.\n",
        "chore: add licence",
    )


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


def test_fixture_unknown_size_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["fixture", "--seed", "0", "--size", "huge", "--out", str(tmp_path / "fixture")]
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
    _commit_licence(repo)
    config = _allow_public_identity_config(tmp_path)
    result = runner.invoke(app, ["scan", str(repo), "--config", str(config)])
    assert result.exit_code == 0
    assert "0 finding(s)" in result.stdout


def test_scan_with_a_secret_exits_1_by_default(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.aws_access_key(random.Random(42))
    commit_file(repo, "config.txt", f'access_key = "{token}"\n', "feat: add config")
    _commit_licence(repo)
    config = _allow_public_identity_config(tmp_path)
    result = runner.invoke(app, ["scan", str(repo), "--config", str(config)])
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
    _commit_licence(repo)
    config = _allow_public_identity_config(tmp_path)
    debug_json = tmp_path / "debug.json"
    result = runner.invoke(
        app, ["scan", str(repo), "--config", str(config), "--debug-json", str(debug_json)]
    )
    assert result.exit_code == 1
    findings = json.loads(debug_json.read_text())
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "npm-access-token"
    assert token not in debug_json.read_text()


# -- reports, --summary-json, --report-dir, config.scan.fail_on, allow/init ----------


def test_scan_writes_json_md_html_reports_to_the_default_location(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    _commit_licence(repo)
    config = _allow_public_identity_config(tmp_path)
    result = runner.invoke(app, ["scan", str(repo), "--config", str(config)])
    assert result.exit_code == 0
    assert "reports written to " in result.stdout
    report_dir = Path(result.stdout.rsplit("reports written to ", 1)[1].strip())
    assert (report_dir / "report.json").is_file()
    assert (report_dir / "report.md").is_file()
    assert (report_dir / "report.html").is_file()
    assert (report_dir.parent / "latest").resolve() == report_dir


def test_scan_report_dir_override_is_honored(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    _commit_licence(repo)
    config = _allow_public_identity_config(tmp_path)
    out = tmp_path / "my-reports"
    result = runner.invoke(
        app, ["scan", str(repo), "--config", str(config), "--report-dir", str(out)]
    )
    assert result.exit_code == 0
    assert (out / "report.json").is_file()


def test_scan_report_dir_inside_scanned_repo_is_refused(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    result = runner.invoke(app, ["scan", str(repo), "--report-dir", str(repo / "reports")])
    assert result.exit_code == 2


def test_scan_summary_json_prints_only_json_on_stdout(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.aws_access_key(random.Random(46))
    commit_file(repo, "config.txt", f'access_key = "{token}"\n', "feat: add config")
    _commit_licence(repo)
    config = _allow_public_identity_config(tmp_path)
    result = runner.invoke(app, ["scan", str(repo), "--config", str(config), "--summary-json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["groups"]["A"] == 1
    assert payload["by_category"]["secret"] == 1
    assert payload["blocking"] == 1
    assert payload["exit_code"] == 1
    assert Path(payload["reports"]["json"]).is_file()
    assert token not in result.stdout


def test_scan_quiet_suppresses_human_readable_output(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    _commit_licence(repo)
    config = _allow_public_identity_config(tmp_path)
    result = runner.invoke(app, ["scan", str(repo), "--config", str(config), "--quiet"])
    assert result.exit_code == 0
    assert result.stdout == ""


def test_scan_honors_config_fail_on_without_the_flag(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    value = tok.generic_high_entropy_value(random.Random(47))
    commit_file(repo, "config.txt", f'password = "{value}"\n', "feat: add password")
    _commit_licence(repo)
    config = tmp_path / "go-public.toml"
    config.write_text(
        '[identity]\nallow = ["Pat Public <pat@example.com>"]\n[scan]\nfail_on = "critical"\n'
    )
    result = runner.invoke(app, ["scan", str(repo), "--config", str(config)])
    assert result.exit_code == 0  # a high-severity generic-entropy finding, fail_on=critical


def test_allow_appends_fingerprint_to_xdg_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    repo = tmp_path / "repo"
    repo.mkdir()
    result = runner.invoke(
        app, ["allow", "abc123", "--reason", "known test value", "--repo", str(repo)]
    )
    assert result.exit_code == 0
    written = xdg / "go-public" / f"{repo.name}.toml"
    assert written.is_file()
    assert "abc123" in written.read_text()
    assert "known test value" in written.read_text()


def test_allow_without_reason_exits_2(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    result = runner.invoke(app, ["allow", "abc123", "--reason", " ", "--repo", str(repo)])
    assert result.exit_code == 2


def test_allow_rotated_resolves_group_id_from_latest_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    xdg_config = tmp_path / "xdg-config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_config))

    repo = init_repo(tmp_path / "repo")
    token = tok.aws_access_key(random.Random(48))
    commit_file(repo, "config.txt", f'access_key = "{token}"\n', "feat: add config")
    _commit_licence(repo)
    identity_config = _allow_public_identity_config(tmp_path)
    scan_result = runner.invoke(app, ["scan", str(repo), "--config", str(identity_config)])
    assert scan_result.exit_code == 1

    debug_json = tmp_path / "debug.json"
    runner.invoke(
        app, ["scan", str(repo), "--config", str(identity_config), "--debug-json", str(debug_json)]
    )
    fingerprint = json.loads(debug_json.read_text())[0]["fingerprint"]

    result = runner.invoke(
        app,
        ["allow", fingerprint, "--reason", "rotated in vault", "--rotated", "--repo", str(repo)],
    )
    assert result.exit_code == 0
    written = xdg_config / "go-public" / f"{repo.name}.toml"
    assert "rotated in vault" in written.read_text()


def test_allow_rotated_refuses_non_secret_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")  # no licence -> licence-missing-at-head finding
    debug_json = tmp_path / "debug.json"
    runner.invoke(app, ["scan", str(repo), "--debug-json", str(debug_json)])
    fingerprint = next(
        f["fingerprint"]
        for f in json.loads(debug_json.read_text())
        if f["rule_id"] == "licence-missing-at-head"
    )

    result = runner.invoke(
        app, ["allow", fingerprint, "--reason", "n/a", "--rotated", "--repo", str(repo)]
    )
    assert result.exit_code == 2


def test_init_writes_template_with_identities_and_refuses_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")

    result = runner.invoke(app, ["init", str(repo)])
    assert result.exit_code == 0
    written = tmp_path / "xdg" / "go-public" / "repo.toml"
    assert written.is_file()
    assert "Pat Public <pat@example.com>" in written.read_text()
    assert str(repo.resolve()) in written.read_text()

    again = runner.invoke(app, ["init", str(repo)])
    assert again.exit_code == 2


def test_path_rule_finding_is_not_at_the_export_ref_when_only_another_path_holds_the_blob(
    tmp_path: Path,
) -> None:
    # The key-store rule fires on the file name. The same bytes still sit at HEAD under
    # a harmless name; the flagged path is gone, so the finding is not "at HEAD".
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "secrets/wallet.p12", "not really a key store\n", "feat: add store")
    commit_file(repo, "notes.txt", "not really a key store\n", "feat: same bytes")
    _commit_licence(repo)
    git(repo, "rm", "-q", "secrets/wallet.p12")
    ident = {
        "GIT_AUTHOR_NAME": "Pat Public",
        "GIT_AUTHOR_EMAIL": "pat@example.com",
        "GIT_COMMITTER_NAME": "Pat Public",
        "GIT_COMMITTER_EMAIL": "pat@example.com",
    }
    git(repo, "commit", "-q", "-m", "chore: drop the store", env=ident)
    config = _allow_public_identity_config(tmp_path)
    debug_json = tmp_path / "debug.json"
    runner.invoke(
        app, ["scan", str(repo), "--config", str(config), "--debug-json", str(debug_json)]
    )
    findings = [f for f in json.loads(debug_json.read_text()) if f["rule_id"] == "pkcs12-file"]
    assert len(findings) == 1
    assert findings[0]["location"]["paths"] == ["secrets/wallet.p12"]
    assert findings[0]["present_at_export_ref"] is False
