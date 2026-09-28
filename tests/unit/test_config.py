"""`config.py`: defaults, strict unknown-key rejection, minimal `--config` loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from go_public.config import Config, discover_config, load_config, xdg_config_path
from go_public.errors import ConfigError
from go_public.git.runner import GitRunner

from ..conftest import commit_file, init_repo


def test_defaults_match_architecture() -> None:
    config = Config()
    assert config.scan.fail_on == "high"
    assert config.scan.max_scan_mb == 10
    assert config.scan.jobs == 0
    assert config.secrets.generic_entropy == 4.3
    assert config.secrets.gitleaks_config == ""
    assert config.pii.phone_regions == ["US", "GB", "DE"]
    assert "/tmp/" in config.paths.allowed_prefixes
    assert ".internal" in config.network.internal_suffixes
    assert config.export.message == "Initial public release"


def test_load_config_with_no_path_returns_defaults() -> None:
    assert load_config(None) == Config()


def test_load_config_reads_a_toml_file(tmp_path: Path) -> None:
    config_path = tmp_path / "go-public.toml"
    config_path.write_text('[scan]\nfail_on = "medium"\njobs = 4\n')
    config = load_config(config_path)
    assert config.scan.fail_on == "medium"
    assert config.scan.jobs == 4
    assert config.scan.max_scan_mb == 10  # unset tables/keys keep their defaults


def test_unknown_top_level_key_is_a_config_error(tmp_path: Path) -> None:
    config_path = tmp_path / "go-public.toml"
    config_path.write_text('[bogus]\nkey = "value"\n')
    with pytest.raises(ConfigError):
        load_config(config_path)


def test_unknown_key_inside_a_known_table_is_a_config_error(tmp_path: Path) -> None:
    config_path = tmp_path / "go-public.toml"
    config_path.write_text('[scan]\nfail_on = "high"\nbogus_key = 1\n')
    with pytest.raises(ConfigError):
        load_config(config_path)


def test_missing_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "does-not-exist.toml")


def test_invalid_toml_is_a_config_error(tmp_path: Path) -> None:
    config_path = tmp_path / "go-public.toml"
    config_path.write_text("this is not [ valid toml")
    with pytest.raises(ConfigError):
        load_config(config_path)


def test_allowlist_and_rotated_fingerprints_round_trip(tmp_path: Path) -> None:
    config_path = tmp_path / "go-public.toml"
    config_path.write_text(
        '[allowlist]\nfingerprints = [{ id = "abc123", reason = "public test vector" }]\n'
    )
    config = load_config(config_path)
    assert config.allowlist.fingerprints[0].id == "abc123"
    assert config.allowlist.fingerprints[0].reason == "public test vector"


# -- discovery (stage 4) -------------------------------------------------------------


def test_xdg_config_path_uses_repo_dir_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    repo = tmp_path / "myrepo"
    assert xdg_config_path(repo) == tmp_path / "xdg" / "go-public" / "myrepo.toml"


def test_discover_config_explicit_wins_over_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GO_PUBLIC_CONFIG", "/should-not-be-used.toml")
    repo = tmp_path / "repo"
    repo.mkdir()
    explicit = tmp_path / "explicit.toml"
    explicit.write_text('[scan]\nfail_on = "critical"\n')

    result = discover_config(explicit=explicit, repo=repo)

    assert result.config.scan.fail_on == "critical"
    assert result.source == str(explicit)
    assert result.warnings == []


def test_discover_config_falls_back_to_env_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_config = tmp_path / "env.toml"
    env_config.write_text('[scan]\nfail_on = "low"\n')
    monkeypatch.setenv("GO_PUBLIC_CONFIG", str(env_config))
    repo = tmp_path / "repo"
    repo.mkdir()

    result = discover_config(explicit=None, repo=repo)

    assert result.config.scan.fail_on == "low"
    assert result.source == f"env:{env_config}"


def test_discover_config_uses_xdg_file_when_repo_path_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GO_PUBLIC_CONFIG", raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    xdg_path = xdg_config_path(repo)
    xdg_path.parent.mkdir(parents=True)
    xdg_path.write_text(f'[repo]\npath = "{repo}"\n[scan]\nfail_on = "medium"\n')

    result = discover_config(explicit=None, repo=repo)

    assert result.config.scan.fail_on == "medium"
    assert result.source == str(xdg_path)
    assert result.warnings == []


def test_discover_config_ignores_xdg_file_naming_a_different_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GO_PUBLIC_CONFIG", raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    xdg_path = xdg_config_path(repo)
    xdg_path.parent.mkdir(parents=True)
    xdg_path.write_text('[repo]\npath = "/some/other/repo"\n[scan]\nfail_on = "low"\n')

    result = discover_config(explicit=None, repo=repo)

    assert result.config == Config()
    assert result.source == "defaults"
    assert len(result.warnings) == 1
    assert "different repository" in result.warnings[0]


def test_discover_config_reads_only_the_allowlist_from_a_tracked_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GO_PUBLIC_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no-xdg-file-here"))
    repo = init_repo(tmp_path / "repo")
    commit_file(
        repo,
        ".go-public.toml",
        '[allowlist]\nfingerprints = [{ id = "abc", reason = "ok" }]\n[deny]\nterms = ["nope"]\n',
        "chore: config",
    )
    runner = GitRunner(repo, role="source")

    result = discover_config(explicit=None, repo=repo, runner=runner)

    assert result.config.allowlist.fingerprints[0].id == "abc"
    assert result.config.deny.terms == []  # only [allowlist] is read from a tracked config
    assert result.source == ".go-public.toml@HEAD"


def test_discover_config_with_no_config_anywhere_is_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GO_PUBLIC_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no-xdg-file-here"))
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hello\n", "feat: a")
    runner = GitRunner(repo, role="source")

    result = discover_config(explicit=None, repo=repo, runner=runner)

    assert result.config == Config()
    assert result.source == "defaults"
