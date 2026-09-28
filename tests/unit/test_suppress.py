"""`suppress.py`: config fingerprint/group, path-glob, identity-allow and inline
`go-public:allow` suppression; `[rotated]` never suppresses anything.
"""

from __future__ import annotations

from pathlib import Path

from go_public.config import (
    AllowlistConfig,
    Config,
    FingerprintEntry,
    IdentityConfig,
    RotatedConfig,
)
from go_public.git.inventory import build
from go_public.git.runner import GitRunner
from go_public.model import Finding, FixAction, Location
from go_public.suppress import run as suppress_run

from ..conftest import commit_file, init_repo

_BASE_FIX = FixAction(action="none")


def _finding(
    *,
    fingerprint: str = "fp1",
    group_id: str = "grp1",
    category: str = "pii",
    rule_id: str = "pii-email",
    location: Location | None = None,
) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        group_id=group_id,
        category=category,
        rule_id=rule_id,
        severity="high",
        title="t",
        location=location or Location(kind="path", paths=["a.txt"]),
        location_key="a.txt",
        fix=_BASE_FIX,
    )


def _empty_inventory_and_runner(tmp_path: Path) -> tuple[object, GitRunner]:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hello\n", "feat: a")
    runner = GitRunner(repo, role="source")
    return build(runner), runner


def test_fingerprint_allowlist_suppresses(tmp_path: Path) -> None:
    inventory, runner = _empty_inventory_and_runner(tmp_path)
    finding = _finding(fingerprint="fp1")
    config = Config(
        allowlist=AllowlistConfig(fingerprints=[FingerprintEntry(id="fp1", reason="known")])
    )

    result = suppress_run([finding], config, inventory, runner)

    assert result.kept == []
    assert len(result.suppressed) == 1
    assert result.suppressed[0].source == "config-fingerprint"
    assert result.suppressed[0].reason == "known"


def test_group_id_allowlist_suppresses(tmp_path: Path) -> None:
    inventory, runner = _empty_inventory_and_runner(tmp_path)
    finding = _finding(fingerprint="fp1", group_id="grp1")
    config = Config(
        allowlist=AllowlistConfig(fingerprints=[FingerprintEntry(id="grp1", reason="known group")])
    )

    result = suppress_run([finding], config, inventory, runner)

    assert result.kept == []
    assert result.suppressed[0].source == "config-group"


def test_path_glob_suppresses_only_when_every_path_matches(tmp_path: Path) -> None:
    inventory, runner = _empty_inventory_and_runner(tmp_path)
    all_vendored = _finding(
        fingerprint="fp-a", location=Location(kind="path", paths=["vendor/x.txt"])
    )
    mixed = _finding(
        fingerprint="fp-b",
        location=Location(kind="blob", blob="deadbeef", paths=["vendor/x.txt", "src/y.txt"]),
    )
    config = Config(allowlist=AllowlistConfig(paths=["vendor/**"]))

    result = suppress_run([all_vendored, mixed], config, inventory, runner)

    kept_fps = {f.fingerprint for f in result.kept}
    suppressed_fps = {s.fingerprint for s in result.suppressed}
    assert suppressed_fps == {"fp-a"}
    assert kept_fps == {"fp-b"}


def test_identity_allow_suppresses_identity_finding(tmp_path: Path) -> None:
    inventory, runner = _empty_inventory_and_runner(tmp_path)
    finding = _finding(
        fingerprint="fp1",
        category="identity",
        rule_id="identity",
        location=Location(kind="identity", identity="Pat Public <pat@example.com>"),
    )
    config = Config(identity=IdentityConfig(allow=["Pat Public <pat@example.com>"]))

    result = suppress_run([finding], config, inventory, runner)

    assert result.kept == []
    assert result.suppressed[0].source == "identity-allow"


def test_inline_comment_requires_nonempty_reason(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    content = "line one\nAKIA-not-real  # go-public:allow test fixture value\n"
    commit_file(repo, "a.txt", content, "feat: a")
    runner = GitRunner(repo, role="source")
    inventory = build(runner)
    blob = next(iter(inventory.blob_sizes))
    # only one blob exists (a.txt's content); use it directly rather than looking up
    # by path, since blob ids are content-addressed and test setup doesn't need to
    # recompute git's own hash.
    finding = _finding(
        fingerprint="fp1", location=Location(kind="blob", blob=blob, line=2, paths=["a.txt"])
    )
    config = Config()

    result = suppress_run([finding], config, inventory, runner)

    assert result.kept == []
    assert result.suppressed[0].source == "inline-comment"
    assert result.suppressed[0].reason == "test fixture value"


def test_inline_comment_with_no_reason_does_not_suppress(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "line one\nvalue  # go-public:allow\n", "feat: a")
    runner = GitRunner(repo, role="source")
    inventory = build(runner)
    blob = next(iter(inventory.blob_sizes))
    finding = _finding(
        fingerprint="fp1", location=Location(kind="blob", blob=blob, line=2, paths=["a.txt"])
    )

    result = suppress_run([finding], Config(), inventory, runner)

    assert result.kept == [finding]
    assert result.suppressed == []


def test_rotated_config_never_suppresses(tmp_path: Path) -> None:
    inventory, runner = _empty_inventory_and_runner(tmp_path)
    finding = _finding(fingerprint="fp1", group_id="grp1", category="secret", rule_id="aws")
    rotated = RotatedConfig(fingerprints=[FingerprintEntry(id="grp1", reason="done")])
    config = Config(rotated=rotated)

    result = suppress_run([finding], config, inventory, runner)

    assert result.kept == [finding]
    assert result.suppressed == []


def test_unmatched_finding_is_kept(tmp_path: Path) -> None:
    inventory, runner = _empty_inventory_and_runner(tmp_path)
    finding = _finding(fingerprint="fp1")

    result = suppress_run([finding], Config(), inventory, runner)

    assert result.kept == [finding]
    assert result.suppressed == []
