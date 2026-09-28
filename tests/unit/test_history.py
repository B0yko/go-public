"""`export/history.py`: the pieces that turn scan findings into a rewrite specification."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from go_public.config import Config
from go_public.errors import UsageError
from go_public.export import history
from go_public.export.squash import Identity
from go_public.git.runner import GitRunner
from go_public.model import Finding, FixAction, Location

from ..conftest import commit_file, git, init_repo


def _finding(
    *,
    category: str = "secret",
    rule_id: str = "aws-access-token",
    kind: str = "blob",
    value: str | None = "s3cr3t",
    fingerprint: str = "f1",
    **loc: object,
) -> Finding:
    finding = Finding(
        fingerprint=fingerprint,
        group_id="g",
        category=category,
        rule_id=rule_id,
        severity="high",
        title="t",
        location=Location(kind=kind, **loc),  # type: ignore[arg-type]
        location_key="k",
        fix=FixAction(action="none"),
    )
    if value is not None:
        finding.attach_value(value)
    return finding


def test_collect_values_keys_values_by_the_carrying_object_longest_first() -> None:
    values = history.collect_values(
        [
            _finding(blob="b1", value="abc"),
            _finding(blob="b1", value="abcdef", fingerprint="f2"),
            _finding(blob="b1", value="abc", fingerprint="f3"),
            _finding(category="pii", kind="commit_message", commit="c1", value="jo@x"),
            _finding(category="network", kind="tag_message", tag="t1", value="***REMOVED***"),
        ]
    )
    assert values.blob == {"b1": ["abcdef", "abc"]}
    assert values.commit == {"c1": ["jo@x"]}
    assert values.tag == {"t1": ["***REMOVED***"]}
    assert values.count == 4


def test_collect_values_skips_what_has_other_handling() -> None:
    values = history.collect_values(
        [
            _finding(category="licence", rule_id="licence-proprietary", blob="b1"),
            _finding(category="org-identifier", kind="path", paths=["docs/x"]),
            _finding(category="identity", kind="identity", identity="A <a@example.org>"),
            _finding(category="binary-metadata", kind="binary_field", blob="b2", field="Artist"),
            _finding(category="secret", kind="unreachable_blob", blob="b3"),
            _finding(blob="b4", value=None),
            _finding(blob="b5", value=""),
        ]
    )
    assert values.count == 0


def _inventory(paths: list[str], head: list[str]) -> SimpleNamespace:
    return SimpleNamespace(
        occurrences=[SimpleNamespace(path=p) for p in paths],
        export_tree={p: ("100644", "0" * 40) for p in head},
    )


def test_compute_drop_paths_combines_globs_auto_exclude_and_deny_findings() -> None:
    config = Config.model_validate({"export": {"exclude": ["docs/private/**"]}})
    deny = _finding(
        category="org-identifier", rule_id="deny-term", kind="path", paths=["a/x-co.md"]
    )
    inventory = _inventory(
        [".env", "notes/plan.md", "docs/private/x.md", "a/x-co.md", "src/app.py", "docs/keep.md"],
        ["src/app.py"],
    )

    dropped = history.compute_drop_paths(inventory, [deny], config, auto_exclude=True)  # type: ignore[arg-type]

    assert dropped == [".env", "a/x-co.md", "docs/private/x.md", "notes/plan.md"]


def test_compute_drop_paths_without_auto_exclude_and_with_a_suppressed_deny_path() -> None:
    config = Config()
    inventory = _inventory([".env", "a/x-co.md"], [])

    # The deny finding was suppressed (allowlisted), so it is not among the findings.
    dropped = history.compute_drop_paths(inventory, [], config, auto_exclude=False)  # type: ignore[arg-type]

    assert dropped == []


def test_a_tracked_config_with_a_deny_list_is_dropped_from_history() -> None:
    finding = _finding(
        category="config", rule_id="tracked-config-deny", kind="path", paths=[".go-public.toml"]
    )
    inventory = _inventory([".go-public.toml"], [".go-public.toml"])

    dropped = history.compute_drop_paths(inventory, [finding], Config(), auto_exclude=True)  # type: ignore[arg-type]

    assert dropped == [".go-public.toml"]


def test_deny_paths_at_the_export_ref_are_found() -> None:
    at_head = _finding(
        category="org-identifier",
        rule_id="deny-term",
        kind="path",
        paths=["x"],
    )
    at_head.present_at_export_ref = True
    old = _finding(category="org-identifier", rule_id="deny-term", kind="path", paths=["y"])
    assert history.deny_paths_at_export_ref([at_head, old]) == [at_head]


def test_licence_history_means_a_licence_finding_off_the_export_ref() -> None:
    old = _finding(category="licence", rule_id="licence-transition")
    head = _finding(category="licence", rule_id="licence-proprietary")
    head.present_at_export_ref = True
    assert history.is_licence_history(old) and not history.is_licence_history(head)
    assert not history.is_licence_history(_finding())


def test_resolve_branch(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "r")
    commit_file(repo, "a.txt", "a\n", "feat: a")
    git(repo, "branch", "topic")
    git(repo, "tag", "v1")
    runner = GitRunner(repo, role="source")

    assert history.resolve_branch(runner, "HEAD") == "main"
    assert history.resolve_branch(runner, "topic") == "topic"
    assert history.resolve_branch(runner, "refs/heads/topic") == "topic"
    for bad in ("v1", "refs/tags/v1", "no-such", "HEAD~1"):
        with pytest.raises(UsageError, match="branch"):
            history.resolve_branch(runner, bad)


def test_resolve_branch_on_a_detached_head(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "r")
    commit_file(repo, "a.txt", "a\n", "feat: a")
    git(repo, "checkout", "-q", "--detach")

    with pytest.raises(UsageError, match="detached"):
        history.resolve_branch(GitRunner(repo, role="source"), "HEAD")


def test_the_child_command_keeps_the_working_directory_off_sys_path() -> None:
    command = history.child_command()
    assert command[1:] == ["-P", "-m", "go_public.export._filter_child"]


def test_build_spec_carries_values_but_the_command_line_never_does(tmp_path: Path) -> None:
    config = Config.model_validate({"files": {"high_mb": 7}})
    request = history.HistoryRequest(
        source=tmp_path,
        out=tmp_path / "o",
        ref="HEAD",
        config=config,
        config_source="defaults",
        scan_options=None,  # type: ignore[arg-type]
        git_version="git version 2.50.0",
        fail_on="high",
        author=Identity("Pub Lic", "pub@example.com"),
        mailmap=None,
    )
    values = history.Values(blob={"b1": ["s3cr3t"]}, commit={}, tag={})

    spec = history.build_spec(request, values, [".env"], request.author)

    assert spec["blob_values"] == {"b1": ["s3cr3t"]}
    assert spec["max_blob_bytes"] == 7 * 1024 * 1024
    assert spec["identity"] == {"name": "Pub Lic", "email": "pub@example.com"}
    assert spec["mailmap"] is None
    assert "s3cr3t" not in " ".join(history.child_command())


def test_surviving_objects_reports_what_stays_after_a_second_prune(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "r")
    oid = commit_file(repo, "a.txt", "a\n", "feat: a")
    runner = GitRunner(repo, role="export")
    env = {"GIT_COMMITTER_NAME": "P", "GIT_COMMITTER_EMAIL": "p@example.com"}

    assert history._surviving_objects(runner, {oid}, env) == [oid]
    assert history._surviving_objects(runner, {"0" * 40}, env) == []
    assert history._surviving_objects(runner, set(), env) == []
    assert subprocess.run(["git", "-C", str(repo), "fsck"], capture_output=True).returncode == 0
