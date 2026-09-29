"""`export/precheck.py`'s pure resolvability logic: which findings at the export ref the export
process resolves by itself, and which still block `--fail-on`.
"""

from __future__ import annotations

from go_public.config import Config, ExportConfig, FilesConfig
from go_public.export import precheck
from go_public.model import Finding, FixAction, Location


def _blocking(
    findings: list[Finding],
    *,
    config: Config | None = None,
    fail_on: str = "high",
    strip: bool = True,
) -> list[Finding]:
    return precheck.blocking_findings(
        findings, config=config or Config(), fail_on=fail_on, strip_metadata=strip
    )


def _finding(
    *,
    category: str,
    rule_id: str,
    severity: str = "high",
    paths: list[str] | None = None,
    present_at_export_ref: bool = True,
) -> Finding:
    return Finding(
        fingerprint=f"fp-{rule_id}-{'-'.join(paths or [])}",
        group_id="g",
        category=category,
        rule_id=rule_id,
        severity=severity,
        title="t",
        location=Location(kind="path", paths=paths or []),
        location_key="k",
        present_at_export_ref=present_at_export_ref,
        fix=FixAction(action="none"),
    )


def test_history_only_finding_never_blocks() -> None:
    finding = _finding(category="pii", rule_id="pii-email", present_at_export_ref=False)

    assert _blocking([finding]) == []


def test_below_fail_on_never_blocks() -> None:
    finding = _finding(category="pii", rule_id="pii-email", severity="medium")

    assert _blocking([finding]) == []


def test_gitlink_never_blocks() -> None:
    finding = _finding(category="large-file", rule_id="gitlink", paths=["vendor/lib"])

    assert _blocking([finding]) == []


def test_tracked_config_deny_never_blocks() -> None:
    finding = _finding(category="config", rule_id="tracked-config-deny", paths=[".go-public.toml"])

    assert _blocking([finding]) == []


def test_export_exclude_path_is_resolved() -> None:
    finding = _finding(category="pii", rule_id="pii-email", paths=["secret/notes.txt"])
    config = Config(export=ExportConfig(exclude=["secret/**"]))

    assert _blocking([finding], config=config) == []


def test_export_exclude_needs_every_path_to_match() -> None:
    finding = _finding(category="pii", rule_id="pii-email", paths=["secret/a.txt", "public/a.txt"])
    config = Config(export=ExportConfig(exclude=["secret/**"]))

    assert _blocking([finding], config=config) == [finding]


def test_sensitive_file_resolved_only_when_auto_exclude_is_on() -> None:
    finding = _finding(category="sensitive-file", rule_id="sensitive-file", paths=[".env"])

    on = Config(files=FilesConfig(auto_exclude=True))
    off = Config(files=FilesConfig(auto_exclude=False))

    assert _blocking([finding], config=on) == []
    assert _blocking([finding], config=off) == [finding]


def test_strippable_binary_metadata_resolved_only_when_stripping_is_on() -> None:
    finding = _finding(category="binary-metadata", rule_id="exif-gps", paths=["photo.jpg"])

    assert _blocking([finding], strip=True) == []
    assert _blocking([finding], strip=False) == [finding]


def test_ooxml_comment_author_always_blocks_even_with_stripping_on() -> None:
    finding = _finding(
        category="binary-metadata", rule_id="ooxml-comment-author", paths=["doc.docx"]
    )

    assert _blocking([finding], strip=True) == [finding]


def test_secret_at_head_always_blocks() -> None:
    finding = _finding(category="secret", rule_id="aws-access-token", paths=["config.py"])

    assert _blocking([finding]) == [finding]
