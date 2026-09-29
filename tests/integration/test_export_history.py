"""History-preserving export end to end (product spec item 15; stage-8.md test list)."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from typer.testing import CliRunner

from go_public.cli import app
from go_public.export import history as history_mod
from go_public.export import strip as strip_mod

from ..conftest import git, init_repo
from . import history_scenario as hs
from .test_immutability import _fingerprint

runner = CliRunner()


def _invoke(
    sc: hs.Scenario, out: Path, reports: Path, *args: str, author: str | None = hs.EXPORT_AUTHOR
):  # type: ignore[no-untyped-def]
    argv = [
        "export",
        str(sc.repo),
        "--keep-history",
        "--out",
        str(out),
        "--config",
        str(sc.config),
        "--report-dir",
        str(reports),
    ]
    if author is not None:
        argv += ["--author", author]
    return runner.invoke(app, [*argv, *args])


@dataclass
class Run:
    scenario: hs.Scenario
    out: Path
    reports: Path
    code: int
    output: str
    fingerprint_before: dict[str, object]
    fingerprint_after: dict[str, object]
    source_objects: set[str]


@pytest.fixture(scope="module")
def isolated(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Module-scoped equivalent of the autouse per-test environment isolation."""
    with pytest.MonkeyPatch.context() as mp:
        home = tmp_path_factory.mktemp("home")
        mp.setenv("HOME", str(home))
        mp.setenv("XDG_CONFIG_HOME", str(home / ".config"))
        mp.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
        mp.setenv("TZ", "UTC")
        mp.delenv("GO_PUBLIC_CONFIG", raising=False)
        for key in list(os.environ):
            if key.startswith("GIT_"):
                mp.delenv(key, raising=False)
        yield home


def _all_objects(repo: Path) -> set[str]:
    out = git(repo, "cat-file", "--batch-all-objects", "--batch-check").decode()
    return {line.split()[0] for line in out.splitlines()}


def _run(tmp: Path, *args: str, branch: str = "main") -> Run:
    sc = hs.build(tmp, branch=branch)
    hs.write_config(sc)
    before = _fingerprint(sc.repo)
    out = tmp / "out"
    result = _invoke(sc, out, tmp / "reports", *args)
    return Run(
        scenario=sc,
        out=out,
        reports=tmp / "reports",
        code=result.exit_code,
        output=result.output,
        fingerprint_before=before,
        fingerprint_after=_fingerprint(sc.repo),
        source_objects=_all_objects(sc.repo),
    )


@pytest.fixture(scope="module")
def plain(isolated: Path, tmp_path_factory: pytest.TempPathFactory) -> Run:
    """The scenario on a branch called `trunk`, exported with default options."""
    return _run(tmp_path_factory.mktemp("plain"), branch="trunk")


@pytest.fixture(scope="module")
def tagged(isolated: Path, tmp_path_factory: pytest.TempPathFactory) -> Run:
    return _run(tmp_path_factory.mktemp("tagged"), "--include-tags")


def _dump(repo: Path) -> bytes:
    """Every object of `repo` in decompressed form, for substring searches."""
    return git(repo, "cat-file", "--batch", "--batch-all-objects")


def _commits(repo: Path) -> list[str]:
    return git(repo, "rev-list", "--all").decode().split()


def _paths_in_history(repo: Path) -> set[str]:
    listing = git(repo, "log", "--all", "--format=", "--name-only", "-z").decode()
    return {p for p in listing.split("\0") if p.strip()}


# -- the rewrite ----------------------------------------------------------------------


def test_export_succeeds_and_is_clean(plain: Run) -> None:
    assert plain.code == 0, plain.output
    assert "CLEAN" in plain.output and "NOT CLEAN" not in plain.output
    assert "commit ids changed and signatures were dropped" in plain.output


def test_history_is_kept_and_the_branch_is_named_main(plain: Run) -> None:
    out = plain.out
    assert git(out, "symbolic-ref", "HEAD").decode().strip() == "refs/heads/main"
    refs = git(out, "for-each-ref", "--format=%(refname)").decode().split()
    assert refs == ["refs/heads/main"]
    assert len(_commits(out)) == 4
    assert (out / "README.md").read_text().endswith("Run `python src/app.py`.\n")
    assert git(out, "status", "--porcelain").decode() == ""


def test_every_author_committer_and_tagger_is_the_export_identity(tagged: Run) -> None:
    out = tagged.out
    rows = git(out, "log", "--all", "--format=%an <%ae>|%cn <%ce>").decode().splitlines()
    assert rows and set(rows) == {f"{hs.EXPORT_AUTHOR}|{hs.EXPORT_AUTHOR}"}
    tag = git(out, "cat-file", "-p", "v1").decode()
    assert f"tagger {hs.EXPORT_AUTHOR} " in tag
    assert hs.DANA["email"] not in _dump(out).decode("utf-8", "replace")


def test_configured_trailers_are_stripped(plain: Run) -> None:
    messages = git(plain.out, "log", "--all", "--format=%B").decode()
    for needle in ("Change-Id", "Signed-off-by", "Reviewed-by", hs.LEE["email"]):
        assert needle not in messages


def test_excluded_sensitive_internal_notes_and_deny_term_paths_leave_every_commit(
    plain: Run,
) -> None:
    paths = _paths_in_history(plain.out)
    assert paths == {
        "LICENSE",
        "README.md",
        "src/app.py",
        "img/photo.jpg",
        "secret.txt",
        "wide.txt",
    }
    company = hs.COMPANY.lower()
    for gone in (".env", "notes/plan.md", "docs/private/x.md", f"docs/{company}-design.md"):
        assert gone not in paths


def test_values_are_replaced_in_blobs_and_messages_and_no_token_survives(plain: Run) -> None:
    out = plain.out
    tokens = plain.scenario.tokens
    root = git(out, "rev-list", "--max-parents=0", "HEAD").decode().strip()
    assert git(out, "show", f"{root}:secret.txt").decode() == "aws = ***REMOVED***\n"
    wide = git(out, "show", f"{root}:wide.txt")
    assert wide[:2] == b"\xff\xfe"
    assert wide.decode("utf-16") == "key = ***REMOVED***\n"
    message = git(out, "log", "-1", "--format=%B", root).decode()
    assert message.startswith("feat: initial import for ***REMOVED***\n\nnote ***REMOVED*** kept")
    dump = _dump(out)
    for value in (*tokens.values(), hs.COMPANY):
        assert value.encode() not in dump
        assert value.encode("utf-16-le") not in dump


def test_annotated_tag_message_is_rewritten(tagged: Run) -> None:
    message = git(tagged.out, "cat-file", "-p", "v1").decode()
    assert message.rstrip().endswith("release one ***REMOVED***")
    assert tagged.scenario.tokens["tag"] not in message


def test_binary_metadata_is_stripped_in_every_commit(plain: Run) -> None:
    out = plain.out
    blobs = 0
    for oid in _all_objects(out):
        if git(out, "cat-file", "-t", oid).decode().strip() != "blob":
            continue
        blobs += 1
        assert strip_mod.describe(git(out, "cat-file", "blob", oid)) == [], oid
    assert blobs
    assert plain.scenario.photo_blob_id not in _all_objects(out)
    root = git(out, "rev-list", "--max-parents=0", "HEAD").decode().strip()
    assert git(out, "cat-file", "-t", f"{root}:img/photo.jpg").decode().strip() == "blob"


def test_blobs_at_or_above_high_mb_are_dropped(plain: Run) -> None:
    out = plain.out
    assert "big.bin" not in _paths_in_history(out)
    assert plain.scenario.big_blob_id not in _all_objects(out)
    assert "1 at or above 2 MB dropped" in plain.output


def test_the_origin_remote_is_gone_and_nothing_names_the_source(plain: Run) -> None:
    out = plain.out
    assert git(out, "remote").decode().strip() == ""
    source = str(plain.scenario.repo).encode()
    for path in (out / ".git").rglob("*"):
        if path.is_file() and "objects" not in path.relative_to(out / ".git").parts:
            assert source not in path.read_bytes(), path
    assert not (out / ".git" / "filter-repo").exists()
    hooks = out / ".git" / "hooks"
    assert not hooks.exists() or list(hooks.iterdir()) == []


def test_reflogs_are_expired(plain: Run) -> None:
    logs = [p for p in (plain.out / ".git" / "logs").rglob("*") if p.is_file()]
    for log in logs:
        assert log.read_text() == "", log


def test_commit_ids_change_and_signatures_are_dropped(plain: Run) -> None:
    out = plain.out
    assert set(_commits(out)).isdisjoint(_commits(plain.scenario.repo))
    for commit in _commits(out):
        assert "gpgsig" not in git(out, "cat-file", "-p", commit).decode()
    source_head = git(plain.scenario.repo, "cat-file", "-p", plain.scenario.commits["c4"]).decode()
    assert "gpgsig" in source_head


def test_no_pre_filter_object_with_a_finding_survives(plain: Run) -> None:
    sc = plain.scenario
    survivors = _all_objects(plain.out) & plain.source_objects
    # Unchanged files (LICENSE, app.py) keep their ids; nothing that carried a finding may.
    carried = {
        git(sc.repo, "rev-parse", f"{sc.commits['c1']}:{name}").decode().strip()
        for name in ("secret.txt", "wide.txt", "img/photo.jpg", "big.bin", ".env")
    }
    assert not (survivors & carried)
    assert not (survivors & set(_commits(sc.repo)))
    assert "still in the export" not in plain.output


def test_the_source_is_unchanged(plain: Run) -> None:
    assert plain.fingerprint_before == plain.fingerprint_after


def test_the_rescan_report_is_outside_the_export_and_has_no_secret(plain: Run) -> None:
    report = json.loads((plain.reports / "report.json").read_text())
    assert report["exit_code"] == 0
    text = (plain.reports / "report.json").read_text()
    for value in plain.scenario.tokens.values():
        assert value not in text
    assert not any(plain.reports in p.parents for p in [plain.out])


# -- tags -----------------------------------------------------------------------------


def test_tags_come_only_with_include_tags(plain: Run, tagged: Run) -> None:
    assert git(plain.out, "tag", "--list").decode().strip() == ""
    listed = git(tagged.out, "tag", "--list").decode().split()
    assert sorted(listed) == ["v0.1", "v1"]
    assert f"{hs.COMPANY.lower()}-1.0" not in listed
    assert "1 tag(s) removed" in tagged.output


def test_tags_are_on_the_rewritten_history(tagged: Run) -> None:
    out = tagged.out
    for tag in ("v0.1", "v1"):
        commit = git(out, "rev-parse", f"{tag}^{{commit}}").decode().strip()
        assert commit in _commits(out)
        ancestor = subprocess.run(
            ["git", "-C", str(out), "merge-base", "--is-ancestor", commit, "HEAD"], check=False
        )
        assert ancestor.returncode == 0


# -- refusals and usage errors -----------------------------------------------------------


def test_a_ref_that_is_not_a_branch_exits_2(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    for ref in ("v1", "refs/tags/v1", sc.commits["c3"], "no-such-branch"):
        out = tmp_path / f"out-{len(ref)}"
        result = _invoke(sc, out, tmp_path / "reports", "--ref", ref)
        assert result.exit_code == 2, (ref, result.output)
        assert "branch" in result.output
        assert not out.exists()


def test_a_detached_head_exits_2(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    git(sc.repo, "update-ref", "--no-deref", "HEAD", sc.commits["c3"])

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports")

    assert result.exit_code == 2, result.output
    assert not (tmp_path / "out").exists()


def test_ref_selects_the_branch(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    git(
        sc.repo,
        "update-ref",
        "refs/heads/topic",
        git(sc.repo, "rev-parse", "main").decode().strip(),
    )
    hs.add_commit(sc.repo, {"other.txt": b"o\n"}, "feat: other", branch="topic")

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports", "--ref", "topic")

    assert result.exit_code == 0, result.output
    assert (tmp_path / "out" / "other.txt").exists()
    assert git(tmp_path / "out", "symbolic-ref", "HEAD").decode().strip() == "refs/heads/main"


def test_missing_identity_exits_2_and_a_mailmap_can_stand_in(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports", author=None)

    assert result.exit_code == 2
    assert "no export identity" in result.output
    assert not (tmp_path / "out").exists()


def test_history_only_options_need_keep_history(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    for flag in ("--include-tags", "--fail-on-licence"):
        result = runner.invoke(
            app,
            [
                "export",
                str(sc.repo),
                "--out",
                str(tmp_path / "out"),
                "--author",
                hs.EXPORT_AUTHOR,
                "--config",
                str(sc.config),
                flag,
            ],
        )
        assert result.exit_code == 2, (flag, result.output)
        assert "--keep-history" in result.output


def test_a_deny_term_in_a_path_at_the_export_ref_is_refused_by_the_precheck(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    hs.add_commit(sc.repo, {f"docs/{hs.COMPANY.lower()}-plan.md": b"plan\n"}, "docs: plan")

    for extra in ((), ("--fail-on", "critical")):
        result = _invoke(sc, tmp_path / "out", tmp_path / "reports", *extra)
        assert result.exit_code == 1, result.output
        assert "renamed at the export ref first" in result.output
        assert not (tmp_path / "out").exists()

    check = runner.invoke(
        app,
        [
            "export",
            str(sc.repo),
            "--keep-history",
            "--check",
            "--config",
            str(sc.config),
            "--fail-on",
            "critical",
        ],
    )
    assert check.exit_code == 1


def test_renaming_the_path_at_head_lets_the_export_through(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    hs.add_commit(sc.repo, {f"docs/{hs.COMPANY.lower()}-plan.md": b"plan\n"}, "docs: plan")
    hs.add_commit(
        sc.repo,
        {f"docs/{hs.COMPANY.lower()}-plan.md": None, "docs/plan.md": b"plan\n"},
        "docs: rename",
    )

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports")

    assert result.exit_code == 0, result.output
    assert "docs/plan.md" in _paths_in_history(tmp_path / "out")
    assert f"docs/{hs.COMPANY.lower()}-plan.md" not in _paths_in_history(tmp_path / "out")


def test_a_secret_at_head_is_refused_and_force_export_then_rewrites_it(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    token = sc.tokens["blob"]
    hs.add_commit(sc.repo, {"config.txt": f"aws = {token}\n".encode()}, "chore: config")

    refused = _invoke(sc, tmp_path / "out", tmp_path / "reports")
    assert refused.exit_code == 1
    assert token not in refused.output
    assert not (tmp_path / "out").exists()

    forced = _invoke(sc, tmp_path / "out", tmp_path / "reports", "--force-export")
    assert forced.exit_code == 0, forced.output
    assert (tmp_path / "out" / "config.txt").read_text() == "aws = ***REMOVED***\n"
    assert token.encode() not in _dump(tmp_path / "out")


def test_check_creates_nothing(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)

    result = runner.invoke(
        app,
        ["export", str(sc.repo), "--keep-history", "--check", "--config", str(sc.config)],
    )

    assert result.exit_code == 0, result.output
    assert "pre-check: clean" in result.output
    assert not (tmp_path / "out").exists()


# -- identities, licences, environment ----------------------------------------------------


def test_a_mailmap_replaces_the_export_identity_and_unmapped_ones_are_not_clean(
    tmp_path: Path,
) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    mailmap = tmp_path / "mailmap"
    mailmap.write_text(
        f"Mapped Dana <mapped-dana@example.com> <{hs.DANA['email']}>\n"
        f"Mapped Lee <mapped-lee@example.com> <{hs.LEE['email']}>\n"
    )
    result = _invoke(
        sc,
        tmp_path / "out",
        tmp_path / "reports",
        "--mailmap",
        str(mailmap),
        "--fail-on",
        "medium",
        author=None,
    )

    people = git(tmp_path / "out", "log", "--format=%an <%ae>|%cn <%ce>").decode().splitlines()
    assert "Mapped Dana <mapped-dana@example.com>|Mapped Dana <mapped-dana@example.com>" in people
    assert any(p.startswith("Mapped Lee ") for p in people)
    assert hs.DANA["email"] not in _dump(tmp_path / "out").decode("utf-8", "replace")
    # The mapped identities are not on the allowlist: the re-scan says so.
    assert result.exit_code == 1, result.output
    assert "NOT CLEAN" in result.output
    assert (tmp_path / "out" / ".git").is_dir()


def _licence_repo(tmp_path: Path) -> hs.Scenario:
    repo = init_repo(tmp_path / "src")
    proprietary = b"All rights reserved. Proprietary and confidential.\n"
    hs.add_commit(repo, {"LICENSE": proprietary, "README.md": b"# Demo\n"}, "feat: start")
    hs.add_commit(repo, {"LICENSE": hs.LICENCE}, "chore: relicense")
    sc = hs.Scenario(
        repo=repo,
        config=tmp_path / "go-public.toml",
        tokens={},
        commits={},
        big_blob_id="",
        photo_blob_id="",
    )
    hs.write_config(sc)
    return sc


def test_licence_history_is_listed_but_does_not_decide_the_exit_code(tmp_path: Path) -> None:
    sc = _licence_repo(tmp_path)

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports")

    assert result.exit_code == 0, result.output
    assert "licence history" in result.output and "not blocking" in result.output
    report = json.loads((tmp_path / "reports" / "report.json").read_text())
    assert any(f["category"] == "licence" for f in report["findings"])
    assert report["plan"]["D"]
    assert report["exit_code"] == 0
    assert "LICENSE" in _paths_in_history(tmp_path / "out")
    old = git(tmp_path / "out", "rev-list", "--max-parents=0", "HEAD").decode().strip()
    assert b"Proprietary" in git(tmp_path / "out", "show", f"{old}:LICENSE")


def test_fail_on_licence_makes_licence_history_decide(tmp_path: Path) -> None:
    sc = _licence_repo(tmp_path)

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports", "--fail-on-licence")

    assert result.exit_code == 1, result.output
    assert "NOT CLEAN" in result.output
    assert (tmp_path / "out" / ".git").is_dir()


def test_a_bare_source_repository_works(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    bare = tmp_path / "src.git"
    git(tmp_path, "clone", "-q", "--bare", str(sc.repo), str(bare))
    bare_sc = hs.Scenario(
        repo=bare,
        config=sc.config,
        tokens=sc.tokens,
        commits=sc.commits,
        big_blob_id="",
        photo_blob_id="",
    )

    result = _invoke(bare_sc, tmp_path / "out", tmp_path / "reports")

    assert result.exit_code == 0, result.output
    assert len(_commits(tmp_path / "out")) == 4


def test_a_hostile_user_git_environment_leaves_no_trace_in_the_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    marker = tmp_path / "hook-ran"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    for name in ("post-checkout", "post-commit", "reference-transaction", "pre-auto-gc"):
        hook = hooks / name
        hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
        hook.chmod(0o755)
    global_config = tmp_path / "gitconfig"
    global_config.write_text(
        f"[user]\n\tname = Someone Else\n\temail = someone@corp-elsewhere.invalid\n"
        f"[core]\n\thooksPath = {hooks}\n[init]\n\ttemplateDir = {hooks}\n"
        "[gc]\n\tauto = 1\n[commit]\n\tgpgsign = true\n"
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Env Author")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "env@corp-elsewhere.invalid")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "nowhere"))

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports")

    for name in ("GIT_CONFIG_GLOBAL", "GIT_AUTHOR_NAME", "GIT_COMMITTER_EMAIL", "GIT_DIR"):
        monkeypatch.delenv(name)
    assert result.exit_code == 0, result.output
    assert not marker.exists()
    dump = _dump(tmp_path / "out").decode("utf-8", "replace")
    assert "corp-elsewhere" not in dump and "Env Author" not in dump
    for path in (tmp_path / "out" / ".git").rglob("*"):
        if path.is_file() and "objects" not in path.relative_to(tmp_path / "out" / ".git").parts:
            assert b"corp-elsewhere" not in path.read_bytes(), path


def test_a_repository_file_named_like_a_module_is_never_imported(tmp_path: Path) -> None:
    # The child runs inside the clone, whose files come from the audited repository.
    work = tmp_path / "clone"
    work.mkdir()
    marker = work / "imported-marker"
    evil = "open('imported-marker', 'w').write('x')\n"
    for name in ("json.py", "git_filter_repo.py", "os.py"):
        (work / name).write_text(evil)

    proc = subprocess.run(
        history_mod.child_command(), cwd=work, input=b"{}", capture_output=True, check=False
    )

    assert proc.returncode == 2, proc.stderr
    assert b"bad specification" in proc.stderr
    assert not marker.exists()


def test_an_export_with_module_named_files_in_the_repository_works(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    evil = b"open('imported-marker', 'w').write('x')\n"
    hs.add_commit(sc.repo, {"git_filter_repo.py": evil, "json.py": evil}, "chore: files")

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports")

    assert result.exit_code == 0, result.output
    assert not (tmp_path / "out" / "imported-marker").exists()
    assert (tmp_path / "out" / "json.py").read_bytes() == evil


def test_a_failing_child_removes_the_export_and_exits_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    monkeypatch.setattr(
        history_mod,
        "child_command",
        lambda: ["python3", "-c", "import sys; print('boom', file=sys.stderr); sys.exit(4)"],
    )

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports")

    assert result.exit_code == 3, result.output
    assert "git-filter-repo failed" in result.output and "boom" in result.output
    assert not (tmp_path / "out").exists()
    assert _fingerprint(sc.repo)["refs"] == git(
        sc.repo, "for-each-ref", "--format=%(refname) %(objectname)"
    )


def test_the_specification_never_reaches_argv_or_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    seen: list[list[str]] = []
    real_run = subprocess.run

    def spy(cmd: list[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        seen.append(list(cmd))
        return real_run(cmd, *args, **kwargs)  # type: ignore[call-overload, no-any-return]

    monkeypatch.setattr(history_mod.subprocess, "run", spy)

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports")

    assert result.exit_code == 0, result.output
    child = [c for c in seen if "go_public.export._filter_child" in c]
    assert len(child) == 1
    for value in sc.tokens.values():
        assert not any(value in part for part in child[0])
    for path in (tmp_path / "reports").rglob("*"):
        if path.is_file():
            for value in sc.tokens.values():
                assert value.encode() not in path.read_bytes(), path


# -- allowlists, categories, switches -----------------------------------------------------


def test_an_allowlisted_location_keeps_its_value_and_the_rest_is_replaced(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc, '[allowlist]\npaths = ["docs/example.txt"]\n')
    example = sc.tokens["message"]
    hs.add_commit(sc.repo, {"docs/example.txt": f"token = {example}\n".encode()}, "docs: example")
    hs.add_commit(sc.repo, {"docs/example.txt": b"see the docs\n"}, "docs: shorten")

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports")

    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    versions = git(out, "log", "--format=%H", "--", "docs/example.txt").decode().split()
    old = git(out, "show", f"{versions[-1]}:docs/example.txt").decode()
    assert old == f"token = {example}\n"
    # The same value in the first commit's message sat in a different, unallowlisted place.
    root = git(out, "rev-list", "--max-parents=0", "HEAD").decode().strip()
    assert example not in git(out, "log", "-1", "--format=%B", root).decode()


def test_other_categories_are_replaced_too(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    local = "/Us" + "ers/" + "jdoe" + "/work/app"
    email = "jo" + "@" + "acme-mail.io"
    host = "build01." + "corp" + ".local"
    body = f"path={local}\nmail={email}\nhost={host}\n".encode()
    hs.add_commit(sc.repo, {"old.txt": body}, "chore: old")
    hs.add_commit(sc.repo, {"old.txt": None}, "chore: drop old")

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports")

    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    commit = git(out, "log", "--format=%H", "--diff-filter=A", "--", "old.txt").decode().split()[0]
    assert git(out, "show", f"{commit}:old.txt").decode() == (
        "path=***REMOVED***work/app\nmail=***REMOVED***\nhost=***REMOVED***\n"
    )
    dump = _dump(out).decode("utf-8", "replace")
    for value in (local, email, host):
        assert value not in dump


def test_no_strip_keeps_history_metadata_and_the_rescan_reports_it(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports", "--no-strip")

    assert result.exit_code == 1, result.output
    assert "NOT CLEAN" in result.output and "binary-metadata" in result.output
    assert sc.photo_blob_id in _all_objects(tmp_path / "out")


def test_a_tracked_config_with_a_deny_list_leaves_the_whole_history(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    hs.add_commit(sc.repo, {".go-public.toml": b'[deny]\nterms = ["zzq-internal"]\n'}, "chore: cfg")

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports")

    assert result.exit_code == 0, result.output
    assert ".go-public.toml" not in _paths_in_history(tmp_path / "out")
    assert b"zzq-internal" not in _dump(tmp_path / "out")


def test_gitlinks_never_reach_the_history_export(tmp_path: Path) -> None:
    sc = hs.build(tmp_path)
    hs.write_config(sc)
    repo = sc.repo
    git(repo, "read-tree", "HEAD")
    entry = f"160000,{'1' * 40},vendor/lib"
    git(repo, "update-index", "--add", "--cacheinfo", entry)
    git(repo, "commit", "-q", "-m", "chore: add a submodule entry")
    git(repo, "update-index", "--force-remove", "vendor/lib")
    git(repo, "commit", "-q", "-m", "chore: drop the submodule entry")
    git(repo, "update-index", "--add", "--cacheinfo", entry)
    git(repo, "commit", "-q", "-m", "chore: add it again")

    result = _invoke(sc, tmp_path / "out", tmp_path / "reports")

    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    # The three commits that only touched the entry became empty and are pruned.
    assert len(_commits(out)) == len(_commits(repo)) - 3
    for commit in _commits(out):
        assert "160000" not in git(out, "ls-tree", "-r", commit).decode(), commit
