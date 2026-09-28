"""`detect/files.py`: sensitive/internal-notes files and the tracked-config check."""

from __future__ import annotations

from go_public.config import Config
from go_public.detect.files import FilesDetector, check_tracked_config


def _detector() -> FilesDetector:
    config = Config()
    return FilesDetector(
        sensitive_files=tuple(config.files.sensitive_files),
        internal_notes=tuple(config.files.internal_notes),
    )


def test_env_file_is_critical() -> None:
    hits = _detector().detect_path(".env")
    assert [(d.rule_id, d.severity) for d in hits] == [("sensitive-file", "critical")]


def test_env_example_is_excluded() -> None:
    assert _detector().detect_path(".env.example") == []


def test_private_key_is_critical() -> None:
    hits = _detector().detect_path("keys/id_rsa")
    assert [(d.rule_id, d.severity) for d in hits] == [("sensitive-file", "critical")]


def test_sql_dump_is_high_not_critical() -> None:
    hits = _detector().detect_path("backup/dump.sql")
    assert [(d.rule_id, d.severity) for d in hits] == [("sensitive-file", "high")]


def test_internal_notes_path_is_detected() -> None:
    hits = _detector().detect_path("internal/roadmap.md")
    assert [(d.rule_id, d.severity) for d in hits] == [("internal-notes", "medium")]


def test_ordinary_path_is_not_flagged() -> None:
    assert _detector().detect_path("src/util.py") == []


def test_tracked_config_with_deny_terms_is_flagged() -> None:
    content = b'[deny]\nterms = ["Acme Corp"]\n'
    finding = check_tracked_config(content)
    assert finding is not None
    assert finding.rule_id == "tracked-config-deny"
    assert finding.severity == "critical"


def test_tracked_config_with_empty_deny_is_not_flagged() -> None:
    content = b'[deny]\nterms = []\n\n[identity]\nallow = ["Pat Public <pat@example.com>"]\n'
    assert check_tracked_config(content) is None


def test_tracked_config_without_deny_table_is_not_flagged() -> None:
    content = b'[identity]\nallow = ["Pat Public <pat@example.com>"]\n'
    assert check_tracked_config(content) is None


def test_tracked_config_invalid_toml_is_not_flagged() -> None:
    assert check_tracked_config(b"not valid toml [[[") is None
