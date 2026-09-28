"""`detect/gitleaks_config.py`: loading and strict validation of gitleaks-format TOML.

Ported behaviour from gitleaks v8.30.1's `config` package (config.go, rule.go,
allowlist.go) plus go-public's own strictness (unknown key -> ConfigError).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from go_public.detect.gitleaks_config import load_gitleaks_config, rules_check
from go_public.errors import ConfigError


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


def test_bundled_config_counts_match_pinned_release() -> None:
    config = load_gitleaks_config()
    result = rules_check(config)
    assert result.summary_line() == (
        "222 rules: 221 content regexes, 1 path-only; 49 allowlist regexes compiled"
    )
    assert result.failures == ()


def test_bundled_config_has_no_warnings() -> None:
    assert load_gitleaks_config().warnings == ()


def test_unknown_top_level_key_exits_as_config_error(tmp_path: Path) -> None:
    path = _write(tmp_path, "bad.toml", 'title = "x"\nbogus = true\n')
    with pytest.raises(ConfigError):
        load_gitleaks_config(path)


def test_unknown_rule_key_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "bad.toml",
        """
        [[rules]]
        id = "r1"
        regex = "abc"
        bogus = "x"
        """,
    )
    with pytest.raises(ConfigError):
        load_gitleaks_config(path)


def test_rule_missing_id_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, "bad.toml", '[[rules]]\nregex = "abc"\n')
    with pytest.raises(ConfigError):
        load_gitleaks_config(path)


def test_rule_without_regex_or_path_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, "bad.toml", '[[rules]]\nid = "r1"\n')
    with pytest.raises(ConfigError):
        load_gitleaks_config(path)


def test_path_only_rule_parses(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "cfg.toml",
        r"""
        [[rules]]
        id = "p12-file"
        path = '''(?i)\.p12$'''
        """,
    )
    config = load_gitleaks_config(path)
    rule = config.rules["p12-file"]
    assert rule.regex is None
    assert rule.path is not None
    result = rules_check(config)
    assert result.path_only_rule_count == 1
    assert result.content_rule_count == 0


def test_secret_group_out_of_range_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "bad.toml",
        """
        [[rules]]
        id = "r1"
        regex = "(a)(b)"
        secretGroup = 5
        """,
    )
    with pytest.raises(ConfigError):
        load_gitleaks_config(path)


def test_allowlist_requires_at_least_one_criterion(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "bad.toml",
        """
        [[rules]]
        id = "r1"
        regex = "abc"
        [[rules.allowlists]]
        description = "empty"
        """,
    )
    with pytest.raises(ConfigError):
        load_gitleaks_config(path)


def test_allowlist_invalid_condition_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "bad.toml",
        """
        [[rules]]
        id = "r1"
        regex = "abc"
        [[rules.allowlists]]
        condition = "XOR"
        stopwords = ["x"]
        """,
    )
    with pytest.raises(ConfigError):
        load_gitleaks_config(path)


def test_allowlist_invalid_regex_target_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "bad.toml",
        """
        [[rules]]
        id = "r1"
        regex = "abc"
        [[rules.allowlists]]
        regexTarget = "bogus"
        stopwords = ["x"]
        """,
    )
    with pytest.raises(ConfigError):
        load_gitleaks_config(path)


def test_deprecated_singular_allowlist_conflicts_with_plural(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "bad.toml",
        """
        [[rules]]
        id = "r1"
        regex = "abc"
        [rules.allowlist]
        stopwords = ["x"]
        [[rules.allowlists]]
        stopwords = ["y"]
        """,
    )
    with pytest.raises(ConfigError):
        load_gitleaks_config(path)


def test_deprecated_singular_allowlist_accepted_alone(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "cfg.toml",
        """
        [[rules]]
        id = "r1"
        regex = "abc"
        [rules.allowlist]
        stopwords = ["skip-me"]
        """,
    )
    config = load_gitleaks_config(path)
    assert len(config.rules["r1"].allowlists) == 1


def test_compile_failure_recorded_not_raised(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "cfg.toml",
        r"""
        [[rules]]
        id = "r1"
        path = '''\.env$'''
        regex = '''(unclosed'''
        """,
    )
    config = load_gitleaks_config(path)
    assert config.rules["r1"].regex is None
    assert config.rules["r1"].path is not None
    assert len(config.compile_failures) == 1
    assert "r1" in config.compile_failures[0].context
    result = rules_check(config)
    assert result.failures


def test_target_rules_attach_to_named_rule(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "cfg.toml",
        """
        [[rules]]
        id = "r1"
        regex = "abc"

        [[allowlists]]
        targetRules = ["r1"]
        stopwords = ["skip-me"]
        """,
    )
    config = load_gitleaks_config(path)
    assert config.allowlists == ()
    assert len(config.rules["r1"].allowlists) == 1


def test_target_rules_unknown_id_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "bad.toml",
        """
        [[rules]]
        id = "r1"
        regex = "abc"

        [[allowlists]]
        targetRules = ["does-not-exist"]
        stopwords = ["x"]
        """,
    )
    with pytest.raises(ConfigError):
        load_gitleaks_config(path)


def test_extend_use_default_merges_bundled_rules(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "cfg.toml",
        """
        [extend]
        useDefault = true

        [[rules]]
        id = "my-local-rule"
        regex = "localsecret[0-9]{4}"
        """,
    )
    config = load_gitleaks_config(path)
    assert "my-local-rule" in config.rules
    assert "aws-access-token" in config.rules
    assert len(config.rules) == 223


def test_extend_use_default_overrides_scalar_fields(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "cfg.toml",
        """
        [extend]
        useDefault = true

        [[rules]]
        id = "aws-access-token"
        entropy = 1.5
        """,
    )
    config = load_gitleaks_config(path)
    rule = config.rules["aws-access-token"]
    assert rule.entropy == 1.5
    assert rule.regex is not None  # kept from the bundled rule, not overridden


def test_extend_disabled_rules_drops_bundled_rule(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "cfg.toml",
        """
        [extend]
        useDefault = true
        disabledRules = ["aws-access-token"]

        [[rules]]
        id = "keep-me"
        regex = "abc"
        """,
    )
    config = load_gitleaks_config(path)
    assert "aws-access-token" not in config.rules
    assert "keep-me" in config.rules


def test_extend_path_and_use_default_both_set_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "bad.toml",
        """
        [extend]
        useDefault = true
        path = "other.toml"
        """,
    )
    with pytest.raises(ConfigError):
        load_gitleaks_config(path)


def test_extend_path_relative_to_extending_file(tmp_path: Path) -> None:
    base_dir = tmp_path / "nested"
    base_dir.mkdir()
    _write(
        base_dir,
        "base.toml",
        """
        [[rules]]
        id = "base-rule"
        regex = "basesecret[0-9]{4}"
        """,
    )
    top = _write(
        base_dir,
        "top.toml",
        """
        [extend]
        path = "base.toml"

        [[rules]]
        id = "top-rule"
        regex = "topsecret[0-9]{4}"
        """,
    )
    config = load_gitleaks_config(top)
    assert "base-rule" in config.rules
    assert "top-rule" in config.rules
    assert len(config.rules) == 2


def test_extend_path_drops_overlay_only_required_and_skip_report(tmp_path: Path) -> None:
    """Ports `Config.extend` (config.go): for a rule present in both the extending
    file and the base it extends, `extend()` only ever copies the base rule's
    `RequiredRules`/`SkipReport` into the merged rule — the *overlay*'s values for
    those two fields are never even read. An overlay-only `required`/`skipReport` on
    a rule that also exists in the base is silently dropped, exactly as upstream.
    """
    base_dir = tmp_path / "nested"
    base_dir.mkdir()
    _write(
        base_dir,
        "base.toml",
        """
        [[rules]]
        id = "shared-rule"
        regex = "basesecret[0-9]{4}"
        """,
    )
    top = _write(
        base_dir,
        "top.toml",
        """
        [extend]
        path = "base.toml"

        [[rules]]
        id = "shared-rule"
        entropy = 1.5
        skipReport = true

        [[rules.required]]
        id = "helper-rule"

        [[rules]]
        id = "helper-rule"
        regex = "helpersecret[0-9]{4}"
        """,
    )
    config = load_gitleaks_config(top)
    rule = config.rules["shared-rule"]
    assert rule.entropy == 1.5  # scalar override still applies
    assert rule.skip_report is False  # overlay's skipReport is dropped, matches base
    assert rule.required == ()  # overlay's required is dropped, matches base


def test_min_version_newer_than_pinned_warns(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "cfg.toml",
        """
        minVersion = "v99.0.0"

        [[rules]]
        id = "r1"
        regex = "abc"
        """,
    )
    config = load_gitleaks_config(path)
    assert config.warnings
    assert "99.0.0" in config.warnings[0]
