"""Shared fixtures: environment isolation, and helpers to build scenario repos.

Tests build repos with plain `subprocess` git calls (never through `GitRunner`,
which is what is under test); package code may not do this — see conventions.md.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from go_public.model import (
    Finding,
    InventoryInfo,
    PlanModel,
    RepoInfo,
    Report,
    ScanInfo,
    ScanOptionsInfo,
    SummaryInfo,
    ToolInfo,
)

PUBLIC_IDENT = {"name": "Pat Public", "email": "pat@example.com"}


@pytest.fixture(autouse=True)
def isolated_environment(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never let the developer's real HOME, git config or env leak into a test."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.delenv("GO_PUBLIC_CONFIG", raising=False)
    for key in list(os.environ):
        if key.startswith("GIT_"):
            monkeypatch.delenv(key, raising=False)


def git(repo: Path, *args: str, env: dict[str, str] | None = None, check: bool = True) -> bytes:
    """Run a plain git command against `repo` (test setup only)."""
    full_env = {**os.environ, **(env or {})}
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], env=full_env, capture_output=True, check=check
    )
    return proc.stdout


def init_repo(path: Path, *, bare: bool = False, object_format: str | None = None) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    args = ["init", "-q", "--initial-branch=main"]
    if bare:
        args.append("--bare")
    if object_format:
        args.append(f"--object-format={object_format}")
    git(path, *args)
    git(path, "config", "user.name", PUBLIC_IDENT["name"])
    git(path, "config", "user.email", PUBLIC_IDENT["email"])
    git(path, "config", "commit.gpgsign", "false")
    return path


def commit_file(
    repo: Path,
    relpath: str,
    content: str,
    message: str,
    *,
    date: str = "2024-01-01T00:00:00+00:00",
    author: dict[str, str] | None = None,
) -> str:
    """Write `relpath`, commit it, and return the new commit's oid."""
    file_path = repo / relpath
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content)
    git(repo, "add", relpath)
    ident = author or PUBLIC_IDENT
    env = {
        "GIT_AUTHOR_NAME": ident["name"],
        "GIT_AUTHOR_EMAIL": ident["email"],
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_NAME": ident["name"],
        "GIT_COMMITTER_EMAIL": ident["email"],
        "GIT_COMMITTER_DATE": date,
    }
    git(repo, "commit", "-q", "-m", message, env=env)
    return git(repo, "rev-parse", "HEAD").decode().strip()


def empty_commit(repo: Path, message: str, *, date: str = "2024-01-01T00:00:00+00:00") -> str:
    env = {
        "GIT_AUTHOR_NAME": PUBLIC_IDENT["name"],
        "GIT_AUTHOR_EMAIL": PUBLIC_IDENT["email"],
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_NAME": PUBLIC_IDENT["name"],
        "GIT_COMMITTER_EMAIL": PUBLIC_IDENT["email"],
        "GIT_COMMITTER_DATE": date,
    }
    git(repo, "commit", "-q", "--allow-empty", "-m", message, env=env)
    return git(repo, "rev-parse", "HEAD").decode().strip()


def hash_blob(repo: Path, content: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
        input=content.encode(),
        env=os.environ.copy(),
        capture_output=True,
        check=True,
    )
    return proc.stdout.decode().strip()


def minimal_report(findings: list[Finding] | None = None) -> Report:
    """The smallest valid `model.Report`, for tests that only care about one or two
    fields (`report/*`, `config_write.py`'s report-backed id resolution)."""
    return Report(
        tool=ToolInfo(version="0.1.0"),
        repo=RepoInfo(name="repo", bare=False, object_format="sha1", export_ref="HEAD"),
        scan=ScanInfo(
            started_at="2024-01-01T00:00:00+00:00",
            finished_at="2024-01-01T00:00:01+00:00",
            duration_s=1.0,
            git_version="git version 2.45.0",
            options=ScanOptionsInfo(),
        ),
        inventory=InventoryInfo(refs=0, commits=0, tags=0, unique_blobs=0, total_bytes=0),
        findings=findings or [],
        plan=PlanModel(),
        summary=SummaryInfo(),
        exit_code=0,
    )


def commit_entries(
    repo: Path,
    entries: list[tuple[str, str, bytes | str]],
    message: str = "chore: snapshot",
    *,
    branch: str = "main",
    date: str = "2024-01-01T00:00:00+00:00",
) -> str:
    """Commit exactly `entries` as `branch`'s tree through plumbing, so a scenario can
    hold paths a case-insensitive working tree could not (README.md + readme.md),
    gitlinks, or a bare repository. Each entry is `(mode, path, content_or_oid)`: bytes
    are written as a blob; a str is used as an object id as-is (gitlinks)."""
    git_dir = repo / ".git" if (repo / ".git").exists() else repo
    index = git_dir / "scenario-index.tmp"
    env = {"GIT_INDEX_FILE": str(index)}
    for mode, path, payload in entries:
        if isinstance(payload, bytes):
            oid = (
                subprocess.run(
                    ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
                    input=payload,
                    capture_output=True,
                    check=True,
                )
                .stdout.decode()
                .strip()
            )
        else:
            oid = payload
        git(repo, "update-index", "--add", "--cacheinfo", f"{mode},{oid},{path}", env=env)
    tree = git(repo, "write-tree", env=env).decode().strip()
    index.unlink(missing_ok=True)
    ident_env = {
        "GIT_AUTHOR_NAME": PUBLIC_IDENT["name"],
        "GIT_AUTHOR_EMAIL": PUBLIC_IDENT["email"],
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_NAME": PUBLIC_IDENT["name"],
        "GIT_COMMITTER_EMAIL": PUBLIC_IDENT["email"],
        "GIT_COMMITTER_DATE": date,
    }
    commit = git(repo, "commit-tree", tree, "-m", message, env=ident_env).decode().strip()
    git(repo, "update-ref", f"refs/heads/{branch}", commit)
    return commit
