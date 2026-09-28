"""Inventory building against real repositories: refs, attribution, warnings."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from go_public.errors import UnsupportedRepo
from go_public.git.inventory import build, build_head_only
from go_public.git.runner import GitRunner

from ..conftest import commit_file, git, init_repo


def test_all_ref_kinds_and_peeled_annotated_tag(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    c1 = commit_file(repo, "a.txt", "hi\n", "feat: a")
    git(repo, "tag", "lw", c1)
    git(
        repo,
        "tag",
        "-a",
        "ann",
        "-m",
        "annotated",
        c1,
        env={"GIT_COMMITTER_DATE": "2024-01-01T00:00:00+00:00"},
    )
    git(repo, "update-ref", "refs/remotes/origin/main", c1)
    git(
        repo,
        "notes",
        "add",
        "-m",
        "a note",
        c1,
        env={
            "GIT_AUTHOR_DATE": "2024-01-01T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2024-01-01T00:00:00+00:00",
        },
    )
    git(repo, "update-ref", "refs/stash", c1)
    git(
        repo,
        "update-ref",
        "refs/original/refs/heads/main",
        c1,
        env={"GIT_NO_REPLACE_OBJECTS": "1"},
    )

    runner = GitRunner(repo, role="source")
    inv = build(runner)

    kinds = {r.kind for r in inv.refs}
    assert kinds == {"branch", "tag", "remote", "notes", "stash", "original"}

    ann_ref = next(r for r in inv.refs if r.name == "refs/tags/ann")
    assert ann_ref.target_type == "tag"
    assert ann_ref.peeled == c1
    assert ann_ref.target in inv.tags
    assert inv.tags[ann_ref.target].object == c1

    lw_ref = next(r for r in inv.refs if r.name == "refs/tags/lw")
    assert lw_ref.target_type == "commit"
    assert lw_ref.peeled is None


def test_replace_ref_kind(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    c1 = commit_file(repo, "a.txt", "hi\n", "feat: a")
    c2 = commit_file(repo, "b.txt", "hi2\n", "feat: b", date="2024-01-02T00:00:00+00:00")
    git(repo, "update-ref", f"refs/replace/{c1}", c2, env={"GIT_NO_REPLACE_OBJECTS": "1"})

    runner = GitRunner(repo, role="source")
    inv = build(runner)
    replace_ref = next(r for r in inv.refs if r.kind == "replace")
    assert replace_ref.name == f"refs/replace/{c1}"
    assert replace_ref.target == c2


def test_tag_on_commit_with_no_branch(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    git(repo, "checkout", "-q", "-b", "temp")
    orphan = commit_file(repo, "temp.txt", "temp\n", "feat: temp", date="2024-01-02T00:00:00+00:00")
    git(
        repo,
        "tag",
        "-a",
        "orphan-tag",
        "-m",
        "orphan",
        orphan,
        env={"GIT_COMMITTER_DATE": "2024-01-02T00:00:00+00:00"},
    )
    git(repo, "checkout", "-q", "main")
    git(repo, "branch", "-D", "temp")

    runner = GitRunner(repo, role="source")
    inv = build(runner)
    assert orphan in inv.commits
    tag_ref = next(r for r in inv.refs if r.name == "refs/tags/orphan-tag")
    assert tag_ref.peeled == orphan


def test_root_commit_attribution(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    (repo / "a.txt").write_text("hello\n")
    (repo / "b.txt").write_text("world\n")
    git(repo, "add", "a.txt", "b.txt")
    git(
        repo,
        "commit",
        "-q",
        "-m",
        "feat: root",
        env={
            "GIT_AUTHOR_DATE": "2024-01-01T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2024-01-01T00:00:00+00:00",
        },
    )
    root = git(repo, "rev-parse", "HEAD").decode().strip()

    runner = GitRunner(repo, role="source")
    inv = build(runner)
    assert inv.commits[root].parents == []
    paths = {occ.path for occ in inv.occurrences if occ.commit == root}
    assert paths == {"a.txt", "b.txt"}
    assert len(inv.blob_sizes) == 2


def test_evil_merge_attributed_via_diff_merges_separate(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "shared.txt", "base\n", "feat: base")
    left = commit_file(repo, "shared.txt", "left\n", "feat: left", date="2024-01-02T00:00:00+00:00")
    git(repo, "checkout", "-q", "-b", "side", "HEAD~1")
    right = commit_file(
        repo, "shared.txt", "right\n", "feat: right", date="2024-01-02T00:00:00+00:00"
    )
    git(repo, "checkout", "-q", "main")

    git(repo, "read-tree", left)
    (repo / "shared.txt").write_text("evil\n")
    git(repo, "update-index", "shared.txt")
    tree = git(repo, "write-tree").decode().strip()
    evil_commit = (
        git(
            repo,
            "commit-tree",
            "-p",
            left,
            "-p",
            right,
            "-m",
            "merge: evil",
            tree,
            env={
                "GIT_AUTHOR_DATE": "2024-01-03T00:00:00+00:00",
                "GIT_COMMITTER_DATE": "2024-01-03T00:00:00+00:00",
            },
        )
        .decode()
        .strip()
    )
    git(repo, "update-ref", "refs/heads/main", evil_commit)

    evil_blob = git(repo, "rev-parse", f"{evil_commit}:shared.txt").decode().strip()

    runner = GitRunner(repo, role="source")
    inv = build(runner)
    assert evil_commit in inv.commits
    assert inv.commits[evil_commit].parents == [left, right]
    evil_occurrences = [occ for occ in inv.occurrences if occ.commit == evil_commit]
    assert evil_occurrences, "the evil merge's own content must be attributed to it"
    assert all(occ.blob == evil_blob and occ.path == "shared.txt" for occ in evil_occurrences)
    assert inv.present_at_export_ref(evil_blob)


def test_unreachable_blob_only_with_flag(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    dangling = (
        subprocess.run(
            ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
            input=b"never referenced\n",
            capture_output=True,
            check=True,
        )
        .stdout.decode()
        .strip()
    )

    runner = GitRunner(repo, role="source")
    default_inv = build(runner)
    assert dangling not in default_inv.blob_sizes
    assert dangling not in default_inv.unreachable_blobs

    full_inv = build(runner, include_unreachable=True)
    assert dangling in full_inv.unreachable_blobs
    assert full_inv.unreachable_blobs[dangling] == len(b"never referenced\n")


def test_head_only_skips_history(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hello\n", "feat: a")
    commit_file(repo, "b.txt", "world\n", "feat: b", date="2024-01-02T00:00:00+00:00")

    runner = GitRunner(repo, role="source")
    inv = build_head_only(runner)
    assert inv.head_only is True
    assert inv.refs == []
    assert inv.commits == {}
    assert set(inv.export_tree) == {"a.txt", "b.txt"}
    assert len(inv.blob_sizes) == 2
    assert inv.total_bytes == len("hello\n") + len("world\n")


def test_bare_repo_is_scanned(tmp_path: Path) -> None:
    src = init_repo(tmp_path / "src")
    commit_file(src, "a.txt", "hi\n", "feat: a")
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(src), str(bare)], check=True)

    runner = GitRunner(bare, role="source")
    inv = build(runner)
    assert inv.repo_state.bare is True
    assert len(inv.commits) == 1
    assert len(inv.blob_sizes) == 1


def test_sha256_repo_is_unsupported(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo", object_format="sha256")
    commit_file(repo, "a.txt", "hi\n", "feat: a")

    runner = GitRunner(repo, role="source")
    with pytest.raises(UnsupportedRepo):
        build(runner)
    with pytest.raises(UnsupportedRepo):
        build_head_only(runner)


def test_shallow_clone_warning(tmp_path: Path) -> None:
    src = init_repo(tmp_path / "src")
    commit_file(src, "a.txt", "hi\n", "feat: a")
    commit_file(src, "b.txt", "hi2\n", "feat: b", date="2024-01-02T00:00:00+00:00")
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{src}", str(shallow)], check=True
    )

    runner = GitRunner(shallow, role="source")
    inv = build(runner)
    assert inv.repo_state.shallow is True
    assert any(w.code == "shallow-clone" for w in inv.warnings)


def test_uncommitted_changes_warning(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    (repo / "a.txt").write_text("changed\n")

    runner = GitRunner(repo, role="source")
    inv = build(runner)
    assert inv.uncommitted_changes is True
    assert any(w.code == "uncommitted-changes" for w in inv.warnings)


def test_clean_working_tree_has_no_uncommitted_warning(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")

    runner = GitRunner(repo, role="source")
    inv = build(runner)
    assert inv.uncommitted_changes is False
    assert not any(w.code == "uncommitted-changes" for w in inv.warnings)


def test_lfs_pointer_warning(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    pointer = "version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 1234\n"
    commit_file(repo, "big.bin", pointer, "feat: lfs pointer")

    runner = GitRunner(repo, role="source")
    inv = build(runner)
    assert len(inv.lfs_pointers) == 1
    assert any(w.code == "lfs-pointers" for w in inv.warnings)
