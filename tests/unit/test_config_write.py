"""`config_write.py`: tomlkit round-trips (comments survive), `init`'s template, and
`allow --rotated`'s report-backed id resolution.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from go_public.config import load_config
from go_public.config_write import (
    append_allow_fingerprint,
    append_rotated,
    build_init_template,
    load_document,
    load_latest_report,
    resolve_secret_group_id,
    save_document,
)
from go_public.errors import UsageError
from go_public.model import Finding, FixAction, Location
from go_public.report.location import prepare_report_dir, update_latest_symlink

from ..conftest import minimal_report


def test_build_init_template_lists_identities_as_comments_not_live_entries() -> None:
    text = build_init_template(Path("/some/repo"), ["Pat Public <pat@example.com>"])

    assert 'path = "/some/repo"' in text
    assert "Pat Public <pat@example.com>" in text
    config = _load_config_from_text(text)
    assert config.identity.allow == []  # never auto-added


def _load_config_from_text(text: str) -> object:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "cfg.toml"
        p.write_text(text)
        return load_config(p)


def test_append_allow_fingerprint_preserves_existing_comments(tmp_path: Path) -> None:
    config_path = tmp_path / "go-public.toml"
    config_path.write_text('# a hand-written comment\n[scan]\nfail_on = "medium"\n')

    append_allow_fingerprint(config_path, "abc123", "known test value")

    text = config_path.read_text()
    assert "# a hand-written comment" in text
    assert 'fail_on = "medium"' in text
    config = load_config(config_path)
    assert config.allowlist.fingerprints[0].id == "abc123"
    assert config.allowlist.fingerprints[0].reason == "known test value"


def test_append_allow_fingerprint_twice_keeps_both_entries(tmp_path: Path) -> None:
    config_path = tmp_path / "go-public.toml"
    append_allow_fingerprint(config_path, "fp1", "first")
    append_allow_fingerprint(config_path, "fp2", "second")

    config = load_config(config_path)
    ids = {e.id for e in config.allowlist.fingerprints}
    assert ids == {"fp1", "fp2"}


def test_append_rotated_writes_under_rotated_table_only(tmp_path: Path) -> None:
    config_path = tmp_path / "go-public.toml"

    append_rotated(config_path, "secret-group-1", "rotated in vault")

    config = load_config(config_path)
    assert config.rotated.fingerprints[0].id == "secret-group-1"
    assert config.allowlist.fingerprints == []


def test_load_and_save_document_round_trip(tmp_path: Path) -> None:
    config_path = tmp_path / "go-public.toml"
    config_path.write_text('[scan]\nfail_on = "low" # keep me\n')

    doc = load_document(config_path)
    save_document(config_path, doc)

    assert "# keep me" in config_path.read_text()


def _secret_finding(fingerprint: str, group_id: str) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        group_id=group_id,
        category="secret",
        rule_id="aws-access-token",
        severity="critical",
        title="t",
        location=Location(kind="blob", blob="b1", line=1, column=1),
        location_key="b1:1:1",
        fix=FixAction(action="rotate"),
    )


def _non_secret_finding(fingerprint: str) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        group_id="g-other",
        category="pii",
        rule_id="pii-email",
        severity="high",
        title="t",
        location=Location(kind="path", paths=["a.txt"]),
        location_key="a.txt",
        fix=FixAction(action="none"),
    )


def test_resolve_secret_group_id_by_fingerprint_or_group_id() -> None:
    report = minimal_report(findings=[_secret_finding("fp1", "grp1"), _non_secret_finding("fp2")])

    assert resolve_secret_group_id(report, "fp1") == "grp1"
    assert resolve_secret_group_id(report, "grp1") == "grp1"


def test_resolve_secret_group_id_refuses_non_secret_finding() -> None:
    report = minimal_report(findings=[_non_secret_finding("fp2")])

    with pytest.raises(UsageError):
        resolve_secret_group_id(report, "fp2")


def test_resolve_secret_group_id_refuses_unknown_id() -> None:
    report = minimal_report(findings=[])

    with pytest.raises(UsageError):
        resolve_secret_group_id(report, "nope")


def test_load_latest_report_reads_the_latest_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    report = minimal_report(findings=[])
    report_dir = tmp_path / "state" / "go-public" / "myrepo" / "20240101T000000Z"
    prepare_report_dir(report_dir)
    (report_dir / "report.json").write_text(report.model_dump_json())
    update_latest_symlink(report_dir)

    loaded = load_latest_report("myrepo")

    assert loaded.repo.name == report.repo.name


def test_load_latest_report_raises_when_none_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

    with pytest.raises(UsageError):
        load_latest_report("never-scanned")
