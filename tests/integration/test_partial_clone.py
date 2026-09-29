"""A partial clone whose promisor remote has vanished: no fetch, just a warning.

A partial clone whose promisor remote was deleted: the scan finishes with a
missing-object warning and no fetch attempt, with the promisor path made
unreachable. The source runner's `GIT_NO_LAZY_FETCH=1` (ADR 3) is what makes this
safe; this test is the regression check for it.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from go_public.git.inventory import build
from go_public.git.runner import GitRunner

from ..conftest import commit_file, git, init_repo


def test_missing_objects_warning_without_fetching(tmp_path: Path) -> None:
    src = init_repo(tmp_path / "src")
    git(src, "config", "uploadpack.allowFilter", "true")
    commit_file(src, "a.txt", "hi\n", "feat: a")
    # Change a.txt so its earlier blob is only reachable through history, never
    # the checkout: that's the blob a partial clone leaves unfetched.
    commit_file(src, "a.txt", "hi-changed\n", "feat: a2", date="2024-01-02T00:00:00+00:00")

    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", "--no-local", "--filter=blob:none", str(src), str(clone)],
        check=True,
    )
    # The promisor remote is now gone; GIT_NO_LAZY_FETCH must stop any fetch attempt.
    shutil.rmtree(src)

    runner = GitRunner(clone, role="source")
    inv = build(runner)

    assert inv.missing_objects
    assert any(w.code == "missing-objects" for w in inv.warnings)


def test_scan_never_invokes_the_promisor_remote(tmp_path: Path) -> None:
    """Even with the promisor remote reachable, a source-role scan must not fetch:
    `remote.origin.uploadpack` points at a script that records any invocation."""
    src = init_repo(tmp_path / "src")
    git(src, "config", "uploadpack.allowFilter", "true")
    commit_file(src, "a.txt", "hi\n", "feat: a")
    commit_file(src, "a.txt", "hi-changed\n", "feat: a2", date="2024-01-02T00:00:00+00:00")

    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", "--no-local", "--filter=blob:none", str(src), str(clone)],
        check=True,
    )
    marker = tmp_path / "fetch-attempted"
    spy = tmp_path / "spy.sh"
    spy.write_text(f'#!/bin/sh\ntouch {marker}\nexec git-upload-pack "$@"\n')
    spy.chmod(0o755)
    git(clone, "config", "remote.origin.uploadpack", str(spy))

    runner = GitRunner(clone, role="source")
    inv = build(runner, include_unreachable=True)

    assert inv.missing_objects
    assert not marker.exists()
