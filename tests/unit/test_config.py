"""`config.py`: defaults, strict unknown-key rejection, minimal `--config` loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from go_public.config import Config, load_config
from go_public.errors import ConfigError


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
