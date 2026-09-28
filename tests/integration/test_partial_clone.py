"""A partial clone whose promisor remote has vanished: no fetch, just a warning.

Stage 1 brief (1b): "partial clone whose promisor remote was deleted: scan finishes
with a missing-object warning and no fetch attempt ... by making the promisor path
unreachable". The source runner's `GIT_NO_LAZY_FETCH=1` (ADR 3) is what makes this
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
