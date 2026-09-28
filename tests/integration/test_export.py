"""Squash export end to end (product spec item 14; stage-5.md test list)."""

from __future__ import annotations

import os
import random
from pathlib import Path

import pytest
from typer.testing import CliRunner

from go_public.bench import binaries
from go_public.cli import app
from go_public.git.objects import blob_id

from ..conftest import PUBLIC_IDENT, commit_entries, git, init_repo
from ..unit import secret_tokens as tok

runner = CliRunner()

AUTHOR = "Pub Lic <pub@example.com>"
LICENCE = (
    b"MIT License\n\nPermission is hereby granted, free of charge, to any person "
    b"obtaining a copy of this software.\n"
)
REG = "100644"


def _config(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "go-public.toml"
    path.write_text(
        f'[identity]\nallow = ["{PUBLIC_IDENT["name"]} <{PUBLIC_IDENT["email"]}>"]\n'
        f"[scan]\njobs = 1\n{extra}"
    )
    return path


def _export(
    tmp_path: Path, repo: Path, *args: str, author: str | None = AUTHOR, extra_config: str = ""
) -> tuple[int, str, Path]:
    out = tmp_path / "out"
    argv = [
        "export",
        str(repo),
        "--out",
        str(out),
        "--config",
        str(_config(tmp_path, extra_config)),
        "--report-dir",
        str(tmp_path / "reports"),
    ]
    if author is not None:
        argv += ["--author", author]
    result = runner.invoke(app, [*argv, *args])
    return result.exit_code, result.output, out


def _basic_repo(tmp_path: Path, extra: list[tuple[str, str, bytes | str]] | None = None) -> Path:
    repo = init_repo(tmp_path / "src")
    commit_entries(
        repo,
        [
            (REG, "LICENSE", LICENCE),
            (REG, "README.md", b"# Hello\n"),
            ("100755", "bin/run.sh", b"#!/bin/sh\necho hi\n"),
            ("120000", "link", b"README.md"),
            (REG, "src/app.py", b"print('hi')\n"),
            *(extra or []),
        ],
    )
    git(repo, "reset", "-q", "--hard")
    return repo


def _tree(repo: Path, ref: str = "HEAD") -> dict[str, tuple[str, str]]:
    listing = git(repo, "ls-tree", "-r", "-z", ref).decode()
    tree = {}
    for record in listing.split("\0"):
        if record:
            meta, _, path = record.partition("\t")
            mode, _type, oid = meta.split(" ")
            tree[path] = (mode, oid)
    return tree


def _object_ids(repo: Path) -> set[str]:
    out = git(repo, "cat-file", "--batch-all-objects", "--batch-check").decode()
    return {line.split()[0] for line in out.splitlines()}


def test_unmodified_files_keep_their_blob_ids_and_history_is_one_commit(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    code, output, out = _export(tmp_path, repo)

    assert code == 0, output
    assert "CLEAN" in output
    assert _tree(out) == _tree(repo)
    assert git(out, "rev-list", "--count", "--all").decode().strip() == "1"
    assert git(out, "symbolic-ref", "HEAD").decode().strip() == "refs/heads/main"
    assert (out / "bin" / "run.sh").stat().st_mode & 0o111
    assert (out / "link").is_symlink()
    assert (out / "README.md").read_text() == "# Hello\n"
    assert git(out, "status", "--porcelain").decode() == ""


def test_commit_uses_only_the_export_identity_message_and_date(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    code, output, out = _export(
        tmp_path, repo, "--date", "2020-01-02T03:04:05+00:00", "--message", "Release one"
    )

    assert code == 0, output
    raw = git(out, "cat-file", "-p", "HEAD").decode()
    assert "author Pub Lic <pub@example.com> 1577934245 +0000" in raw
    assert "committer Pub Lic <pub@example.com> 1577934245 +0000" in raw
    assert raw.rstrip().endswith("Release one")
    assert PUBLIC_IDENT["email"] not in raw


def test_default_message_and_now_date(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    code, _output, out = _export(tmp_path, repo)

    assert code == 0
    assert git(out, "log", "-1", "--format=%s").decode().strip() == "Initial public release"
    assert git(out, "log", "-1", "--format=%cd", "--date=format:%Y").decode().strip() >= "2026"


def test_no_remote_no_hooks_local_identity_set(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    code, _output, out = _export(tmp_path, repo)

    assert code == 0
    assert git(out, "remote").decode().strip() == ""
    hooks = out / ".git" / "hooks"
    assert not hooks.exists() or list(hooks.iterdir()) == []
    assert git(out, "config", "--local", "user.name").decode().strip() == "Pub Lic"
    assert git(out, "config", "--local", "user.email").decode().strip() == "pub@example.com"
    assert git(out, "config", "--local", "commit.gpgsign").decode().strip() == "false"
    assert not (out / ".git" / "description").exists()


def test_no_set_identity_leaves_local_identity_unset(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    code, _output, out = _export(tmp_path, repo, "--no-set-identity")

    assert code == 0
    unset = git(out, "config", "--local", "--get", "user.name", check=False).decode().strip()
    assert unset == ""


def test_missing_author_exits_2_and_never_reads_git_config(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)
    home = Path(os.environ["HOME"])
    (home / ".gitconfig").write_text("[user]\n\tname = Someone Else\n\temail = else@example.com\n")

    code, output, out = _export(tmp_path, repo, author=None)

    assert code == 2
    assert "--author" in output
    assert not out.exists()


def test_author_from_config(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    code, output, out = _export(
        tmp_path,
        repo,
        author=None,
        extra_config='[export]\nauthor = "Conf Ig <conf@example.com>"\nmessage = "From config"\n',
    )

    assert code == 0, output
    assert git(out, "log", "-1", "--format=%an <%ae>|%s").decode().strip() == (
        "Conf Ig <conf@example.com>|From config"
    )


def test_malformed_author_exits_2(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    code, _output, out = _export(tmp_path, repo, author="not an identity")

    assert code == 2
    assert not out.exists()


def test_readme_and_readme_both_exported_with_case_collision_warning(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "src", bare=True)
    commit_entries(
        repo,
        [
            (REG, "LICENSE", LICENCE),
            (REG, "README.md", b"upper\n"),
            (REG, "readme.md", b"lower\n"),
        ],
    )

    code, output, out = _export(tmp_path, repo)

    assert code == 0, output
    assert "case-collision" in output
    assert "README.md" in output and "readme.md" in output
    committed = _tree(out)
    assert {"README.md", "readme.md"} <= set(committed)
    assert committed == _tree(repo)


def test_export_of_a_bare_repository(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "src.git", bare=True)
    commit_entries(repo, [(REG, "LICENSE", LICENCE), (REG, "a.txt", b"a\n")])

    code, output, out = _export(tmp_path, repo)

    assert code == 0, output
    assert _tree(out) == _tree(repo)


def test_sensitive_internal_notes_and_excluded_files_are_absent(tmp_path: Path) -> None:
    repo = _basic_repo(
        tmp_path,
        [
            (REG, ".env", b"MODE=dev\n"),
            (REG, "notes/plan.md", b"remember the milk\n"),
            (REG, "deploy/keep.txt", b"keep\n"),
            (REG, "docs/private/design.md", b"design\n"),
        ],
    )

    code, output, out = _export(
        tmp_path, repo, extra_config='[export]\nexclude = ["docs/private/**"]\n'
    )

    assert code == 0, output
    committed = set(_tree(out))
    assert committed == {
        "LICENSE",
        "README.md",
        "bin/run.sh",
        "link",
        "src/app.py",
        "deploy/keep.txt",
    }
    assert not (out / ".env").exists()
    assert ".env" in output and "notes/plan.md" in output


def test_no_auto_exclude_keeps_sensitive_files_but_the_precheck_then_refuses(
    tmp_path: Path,
) -> None:
    repo = _basic_repo(tmp_path, [(REG, "server.pem", b"not really a key\n")])

    code, output, out = _export(tmp_path, repo, "--no-auto-exclude")

    assert code == 1
    assert "sensitive-file" in output
    assert not out.exists()


def test_gitlinks_and_unsupported_modes_are_dropped(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path, [("160000", "vendor/lib", "1" * 40)])

    code, output, out = _export(tmp_path, repo)

    assert code == 0, output
    assert "vendor/lib" not in _tree(out)
    assert "gitlink" in output


def test_tracked_go_public_config_with_deny_entries_is_dropped(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path, [(REG, ".go-public.toml", b'[deny]\nterms = ["acme-internal"]\n')])

    code, output, out = _export(tmp_path, repo)

    assert code == 0, output
    assert ".go-public.toml" not in _tree(out)
    assert not (out / ".go-public.toml").exists()


def test_tracked_allowlist_only_config_is_kept(tmp_path: Path) -> None:
    payload = b'[allowlist]\npaths = ["docs/**"]\n'
    repo = _basic_repo(tmp_path, [(REG, ".go-public.toml", payload)])

    code, _output, out = _export(tmp_path, repo)

    assert code == 0
    assert _tree(out)[".go-public.toml"][1] == blob_id(payload)


def test_binary_metadata_is_stripped_and_pre_strip_bytes_never_reach_the_export(
    tmp_path: Path,
) -> None:
    dirty = binaries.jpeg_with_gps(12.5, 45.25)
    repo = _basic_repo(tmp_path, [(REG, "img/photo.jpg", dirty)])

    code, output, out = _export(tmp_path, repo)

    assert code == 0, output
    assert "stripped metadata from 1 file" in output
    exported = _tree(out)["img/photo.jpg"][1]
    assert exported != blob_id(dirty)
    assert blob_id(dirty) not in _object_ids(out)
    assert (out / "img" / "photo.jpg").read_bytes() != dirty
    # Everything else still keeps its source blob id.
    for path, (_mode, oid) in _tree(repo).items():
        if path != "img/photo.jpg":
            assert _tree(out)[path][1] == oid


def test_no_strip_leaves_the_file_and_the_precheck_refuses_gps(tmp_path: Path) -> None:
    dirty = binaries.jpeg_with_gps(12.5, 45.25)
    repo = _basic_repo(tmp_path, [(REG, "img/photo.jpg", dirty)])

    code, output, out = _export(tmp_path, repo, "--no-strip")

    assert code == 1
    assert "exif-gps" in output
    assert not out.exists()


def test_no_strip_with_force_export_ships_the_bytes_and_reports_not_clean(
    tmp_path: Path,
) -> None:
    dirty = binaries.jpeg_with_gps(12.5, 45.25)
    repo = _basic_repo(tmp_path, [(REG, "img/photo.jpg", dirty)])

    code, output, out = _export(tmp_path, repo, "--no-strip", "--force-export")

    assert code == 1
    assert "NOT CLEAN" in output
    assert _tree(out)["img/photo.jpg"][1] == blob_id(dirty)


def test_precheck_refuses_a_secret_at_head_and_creates_nothing(tmp_path: Path) -> None:
    token = tok.aws_access_key(random.Random(7))
    repo = _basic_repo(tmp_path, [(REG, "config.txt", f"aws = {token}\n".encode())])

    code, output, out = _export(tmp_path, repo)

    assert code == 1
    assert "pre-check" in output
    assert token not in output
    assert not out.exists()


def test_force_export_ships_then_the_rescan_says_not_clean_and_keeps_the_directory(
    tmp_path: Path,
) -> None:
    token = tok.aws_access_key(random.Random(8))
    repo = _basic_repo(tmp_path, [(REG, "config.txt", f"aws = {token}\n".encode())])

    code, output, out = _export(tmp_path, repo, "--force-export")

    assert code == 1
    assert "NOT CLEAN" in output
    assert token not in output
    assert (out / ".git").is_dir()
    assert (out / "config.txt").exists()


def test_history_only_secret_does_not_block_and_is_not_exported(tmp_path: Path) -> None:
    token = tok.aws_access_key(random.Random(9))
    repo = init_repo(tmp_path / "src")
    commit_entries(repo, [(REG, "LICENSE", LICENCE), (REG, "old.txt", f"k = {token}\n".encode())])
    commit_entries(repo, [(REG, "LICENSE", LICENCE), (REG, "new.txt", b"clean\n")], "chore: clean")
    git(repo, "reset", "-q", "--hard")

    code, output, out = _export(tmp_path, repo)

    assert code == 0, output
    assert set(_tree(out)) == {"LICENSE", "new.txt"}
    for oid in _object_ids(out):
        raw = git(out, "cat-file", "-p", oid, check=False)
        assert token.encode() not in raw


def test_check_creates_nothing_and_exits_0_when_clean(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)
    out = tmp_path / "out"

    result = runner.invoke(
        app,
        ["export", str(repo), "--check", "--config", str(_config(tmp_path))],
    )
    with_out = runner.invoke(
        app,
        ["export", str(repo), "--check", "--out", str(out), "--config", str(_config(tmp_path))],
    )

    assert result.exit_code == 0, result.output
    assert "pre-check: clean" in result.output
    assert with_out.exit_code == 0
    assert not out.exists()


def test_check_exits_1_and_lists_blocking_items(tmp_path: Path) -> None:
    token = tok.aws_access_key(random.Random(10))
    repo = _basic_repo(tmp_path, [(REG, "config.txt", f"aws = {token}\n".encode())])
    out = tmp_path / "out"

    result = runner.invoke(
        app,
        ["export", str(repo), "--check", "--out", str(out), "--config", str(_config(tmp_path))],
    )

    assert result.exit_code == 1
    assert "config.txt" in result.output
    assert token not in result.output
    assert not out.exists()


def test_check_does_not_need_an_author(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    result = runner.invoke(
        app, ["export", str(repo), "--check", "--config", str(_config(tmp_path))]
    )

    assert result.exit_code == 0


@pytest.mark.parametrize("kind", ["nonempty", "file", "inside-repo", "repo-itself"])
def test_out_validation_exits_2(tmp_path: Path, kind: str) -> None:
    repo = _basic_repo(tmp_path)
    if kind == "nonempty":
        out = tmp_path / "out"
        out.mkdir()
        (out / "x").write_text("x")
    elif kind == "file":
        out = tmp_path / "out"
        out.write_text("x")
    elif kind == "inside-repo":
        out = repo / "sub" / "export"
    else:
        out = repo

    result = runner.invoke(
        app,
        [
            "export",
            str(repo),
            "--out",
            str(out),
            "--author",
            AUTHOR,
            "--config",
            str(_config(tmp_path)),
        ],
    )

    assert result.exit_code == 2, result.output
    if kind == "inside-repo":
        assert not out.exists()


def test_empty_existing_out_directory_is_accepted(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)
    (tmp_path / "out").mkdir()

    code, output, out = _export(tmp_path, repo)

    assert code == 0, output
    assert (out / "README.md").exists()


def test_out_inside_a_bare_repo_dir_exits_2(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "src.git", bare=True)
    commit_entries(repo, [(REG, "LICENSE", LICENCE)])

    result = runner.invoke(
        app,
        [
            "export",
            str(repo),
            "--out",
            str(repo / "export"),
            "--author",
            AUTHOR,
            "--config",
            str(_config(tmp_path)),
        ],
    )

    assert result.exit_code == 2


def test_report_dir_inside_the_export_is_refused_before_anything_is_written(
    tmp_path: Path,
) -> None:
    repo = _basic_repo(tmp_path)
    out = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "export",
            str(repo),
            "--out",
            str(out),
            "--author",
            AUTHOR,
            "--config",
            str(_config(tmp_path)),
            "--report-dir",
            str(out / "reports"),
        ],
    )

    assert result.exit_code == 2
    assert not out.exists()


def test_ref_selects_the_exported_tree(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)
    commit_entries(repo, [(REG, "LICENSE", LICENCE), (REG, "other.txt", b"o\n")], branch="topic")

    code, output, out = _export(tmp_path, repo, "--ref", "topic")

    assert code == 0, output
    assert set(_tree(out)) == {"LICENSE", "other.txt"}


def test_keep_history_is_not_available_yet(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    code, _output, out = _export(tmp_path, repo, "--keep-history")

    assert code == 2
    assert not out.exists()


def test_rescan_report_is_written_outside_the_export(tmp_path: Path) -> None:
    repo = _basic_repo(tmp_path)

    code, _output, out = _export(tmp_path, repo)

    assert code == 0
    reports = list((tmp_path / "reports").glob("report.*"))
    assert {p.name for p in reports} == {"report.json", "report.md", "report.html"}
    assert not any(p.name.startswith("report.") for p in out.rglob("*"))


def test_failed_export_removes_the_partial_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from go_public.export import squash

    repo = _basic_repo(tmp_path)

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(squash, "_rescan", boom)
    out = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "export",
            str(repo),
            "--out",
            str(out),
            "--author",
            AUTHOR,
            "--config",
            str(_config(tmp_path)),
        ],
    )

    assert isinstance(result.exception, RuntimeError)
    assert not out.exists()
