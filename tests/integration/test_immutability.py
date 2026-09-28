"""The source repository is never modified by a read-only command.

Architecture.md item 17: fingerprint every ref, `count-objects -v`, a hash of
`.git/config`, `HEAD`, the index, and `git --no-optional-locks status --porcelain`,
before and after running a command, and assert it is unchanged. This stage covers
`scan` (`build`/`build_head_only`); later stages extend the same fingerprint to
`show` and both export modes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from go_public.git.inventory import build, build_head_only
from go_public.git.runner import GitRunner

from ..conftest import commit_file, git, init_repo


def _fingerprint(repo: Path) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    refs = git(repo, "for-each-ref")
    counts = git(repo, "count-objects", "-v")
    config_hash = hashlib.sha256((repo / ".git" / "config").read_bytes()).digest()
    head = git(repo, "rev-parse", "HEAD")
    status = git(repo, "--no-optional-locks", "status", "--porcelain")
    return refs, counts, config_hash, head, status


def test_scan_does_not_modify_the_source_repo(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hi\n", "feat: a")
    commit_file(repo, "b.txt", "hi2\n", "feat: b", date="2024-01-02T00:00:00+00:00")
    git(repo, "tag", "-a", "v1.0", "-m", "release", "HEAD")

    before = _fingerprint(repo)
    runner = GitRunner(repo, role="source")
    build(runner, include_unreachable=True)
    build_head_only(runner)
    after = _fingerprint(repo)

    assert before == after
