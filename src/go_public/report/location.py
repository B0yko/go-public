"""Where reports are written: outside the scanned working tree, by default under
`$XDG_STATE_HOME/go-public/<repo-name>/<UTC timestamp>/`, with a `latest` symlink
kept pointing at the newest one. `go-public allow --rotated` (`config_write.py`)
reads that symlink back to find "the latest report for the repo".
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from go_public.errors import UsageError

_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"
_LATEST_NAME = "latest"


def default_report_root() -> Path:
    """`$XDG_STATE_HOME` (default `~/.local/state`) `/go-public`."""
    xdg_state = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg_state) if xdg_state else Path.home() / ".local" / "state"
    return base / "go-public"


def timestamp_dir_name(when: datetime | None = None) -> str:
    moment = when or datetime.now(UTC)
    return moment.astimezone(UTC).strftime(_TIMESTAMP_FORMAT)


def resolve_report_dir(
    *,
    repo_name: str,
    scanned_repo: Path,
    override: Path | None = None,
    when: datetime | None = None,
    protected: Iterable[Path] = (),
) -> Path:
    """The directory this scan's reports go in. Refused (exit 2, via `UsageError`)
    when it would land inside the scanned repository (working tree or bare repo
    directory alike), since reports are written outside the scanned working
    tree. `protected` adds further directories that count as the repository (its work
    tree top level, git directories)."""
    target = (
        override.resolve()
        if override is not None
        else (default_report_root() / repo_name / timestamp_dir_name(when))
    )
    for root in (scanned_repo.resolve(), *protected):
        _refuse_inside_scanned_repo(target, root)
    return target


def _refuse_inside_scanned_repo(target: Path, scanned_repo: Path) -> None:
    if target == scanned_repo or scanned_repo in target.parents:
        raise UsageError(f"refusing to write reports inside the scanned repository: {target}")


def prepare_report_dir(path: Path) -> None:
    """Create `path` (and parents) at mode 0700."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def secure_report_file(path: Path) -> None:
    """Mode 0600."""
    path.chmod(0o600)


def update_latest_symlink(report_dir: Path) -> None:
    """Point `<report_dir's parent>/latest` at `report_dir`. Best-effort: a
    filesystem with no symlink support (rare, e.g. some Windows setups without the
    right privilege) must never fail the scan over this."""
    latest = report_dir.parent / _LATEST_NAME
    try:
        if latest.is_symlink() or latest.exists():
            latest.unlink()
        latest.symlink_to(report_dir.name)
    except OSError:
        pass


def latest_report_dir(repo_name: str) -> Path | None:
    """The most recent report directory for `repo_name`, via its `latest` symlink,
    or `None` when it has never been scanned (or the link is stale/missing).
    `config_write.py`'s `allow --rotated` uses this to resolve secret ids."""
    latest = default_report_root() / repo_name / _LATEST_NAME
    if not latest.exists():
        return None
    return latest.resolve()
