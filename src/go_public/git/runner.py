"""The only door to git: a subprocess wrapper with a per-role subcommand allowlist.

Every git invocation in the package goes through :class:`GitRunner`. Each runner is
bound to one *role* (``source``, ``export``, ``clone`` or ``fixture``) which fixes both
the set of subcommands it may run and the environment variables that constrain what
those subcommands are allowed to do (no network, no pager, no system config, ...).
``push``, ``fetch`` and ``remote`` are on no role's list: go-public never writes to a
remote.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Literal

from go_public.errors import GitError, UnsupportedRepo

Role = Literal["source", "export", "clone", "fixture"]

#: Subcommands every role may run, subject to the per-subcommand restrictions below.
_READ_COMMANDS = {
    "cat-file",
    "rev-list",
    "log",
    "for-each-ref",
    "ls-tree",
    "rev-parse",
    "show-ref",
    "config",
    "count-objects",
    "status",
}

#: Subcommands a role may run in addition to `_READ_COMMANDS`, unrestricted.
_ROLE_EXTRA: dict[Role, set[str]] = {
    "source": set(),
    "export": {
        "init",
        "hash-object",
        "update-index",
        "write-tree",
        "commit-tree",
        "update-ref",
        "config",
        "checkout",
        "clone",
        "reflog",
        "gc",
    },
    "clone": {"clone"},
    "fixture": {
        "init",
        "fast-import",
        "update-ref",
        "symbolic-ref",
        "config",
        "hash-object",
    },
}

#: Never allowed for any role, regardless of arguments.
_FORBIDDEN = {"push", "fetch", "remote"}

_ROLE_ENV: dict[Role, dict[str, str]] = {
    "source": {"GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "none"},
    "export": {"GIT_ALLOW_PROTOCOL": "file"},
    "clone": {"GIT_ALLOW_PROTOCOL": "https"},
    "fixture": {"GIT_ALLOW_PROTOCOL": "none"},
}

_BASE_ENV = {
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_PAGER": "cat",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
}

_LOG_EXTRA_FLAGS = ("--no-ext-diff", "--no-textconv")

_UNSAFE_MARKERS = (
    "detected dubious ownership",
    "unsafe repository",
)
_NOT_A_REPO_MARKERS = ("not a git repository",)

_FILTER_KEY_RE = r"^filter\..*\.(clean|smudge|process|required)$"
_FILTER_KEY_PARSE = re.compile(r"^filter\.(.+)\.(?:clean|smudge|process|required)$", re.IGNORECASE)

_MIN_GIT_VERSION = (2, 44)
_VERSION_RE = re.compile(r"git version (\d+)\.(\d+)(?:\.(\d+))?")


class RunnerViolation(RuntimeError):
    """Raised when go-public's own code asks the runner for a forbidden command.

    This is always a bug in go-public, never a user error: the CLI does not catch it.
    """


def check_git_version(minimum: tuple[int, int] = _MIN_GIT_VERSION) -> str:
    """Return the installed git version string, or raise :class:`GitError`.

    Runs a bare ``git --version`` outside any role's repo binding, since this check
    happens before go-public knows which repository (if any) it is working with.
    """
    try:
        proc = subprocess.run(["git", "--version"], capture_output=True, check=False, text=True)
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc
    match = _VERSION_RE.search(proc.stdout)
    if proc.returncode != 0 or not match:
        raise GitError(f"could not determine the installed git version: {proc.stdout!r}")
    found = (int(match.group(1)), int(match.group(2)))
    if found < minimum:
        raise GitError(
            f"git {found[0]}.{found[1]} is too old; go-public needs "
            f"{minimum[0]}.{minimum[1]} or newer"
        )
    return match.group(0)


class GitRunner:
    """Runs git subprocesses for one repository, restricted to one role's allowlist."""

    def __init__(self, repo: Path, role: Role, git_dir: Path | None = None) -> None:
        self.repo = repo
        self.role = role
        self.git_dir = git_dir

    # -- public API ---------------------------------------------------------

    def run(
        self,
        args: list[str],
        *,
        input: bytes | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
    ) -> bytes:
        """Run a git subcommand to completion and return its stdout."""
        args = self._prepare(args)
        proc = subprocess.run(
            self._base_cmd(args) + args,
            input=input,
            env=self._build_env(env),
            capture_output=True,
            check=False,
        )
        if check and proc.returncode != 0:
            self._raise_for_failure(args, proc.returncode, proc.stderr)
        return proc.stdout

    def popen(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
    ) -> subprocess.Popen[bytes]:
        """Start a long-lived git subprocess (e.g. ``cat-file --batch``)."""
        args = self._prepare(args)
        return subprocess.Popen(
            self._base_cmd(args) + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._build_env(env),
        )

    # -- internals ------------------------------------------------------------

    def _prepare(self, args: list[str]) -> list[str]:
        self._validate(args)
        return self._augment(args)

    def _base_cmd(self, args: list[str] | None = None) -> list[str]:
        cmd = ["git", "-c", "core.quotepath=off", "-c", "core.fsmonitor=false"]
        if args and self._subcommand(args) == "status":
            cmd += self._filter_overrides()
        if self.git_dir is not None:
            cmd += [f"--git-dir={self.git_dir}"]
        cmd += ["-C", str(self.repo)]
        return cmd

    def _filter_overrides(self) -> list[str]:
        """`-c` options that switch off every filter driver the repository's config
        defines. `status` compares stat-dirty files through their clean filter, which
        would otherwise run a command taken from the repository's own config."""
        probe = subprocess.run(
            ["git", "-C", str(self.repo), "config", "--name-only", "--get-regexp", _FILTER_KEY_RE],
            env=self._build_env(None),
            capture_output=True,
            check=False,
        )
        drivers = {
            match.group(1)
            for line in probe.stdout.decode("utf-8", "replace").splitlines()
            if (match := _FILTER_KEY_PARSE.match(line.strip()))
        }
        overrides: list[str] = []
        for driver in sorted(drivers):
            for key, value in (
                ("clean", ""),
                ("smudge", ""),
                ("process", ""),
                ("required", "false"),
            ):
                overrides += ["-c", f"filter.{driver}.{key}={value}"]
        return overrides

    @staticmethod
    def _subcommand(args: list[str]) -> str | None:
        for token in args:
            if not token.startswith("-"):
                return token
        return None

    def _validate(self, args: list[str]) -> None:
        sub = self._subcommand(args)
        if sub is None:
            raise RunnerViolation(f"no git subcommand found in {args!r}")
        if sub in _FORBIDDEN:
            raise RunnerViolation(f"git {sub} is never permitted (role={self.role})")
        extra = _ROLE_EXTRA[self.role]
        if sub not in _READ_COMMANDS and sub not in extra:
            raise RunnerViolation(f"git {sub} is not allowed for role={self.role!r}")
        # Only reachable via the read-only allowlist: `config --get` alone,
        # never `--get-all` or a write form.
        if sub == "config" and sub not in extra and ("--get" not in args or "--get-all" in args):
            raise RunnerViolation(
                f"git config is only allowed as `config --get` for role={self.role!r}"
            )
        if sub == "status" and "--porcelain" not in args:
            raise RunnerViolation("git status is only allowed with --porcelain")

    @staticmethod
    def _augment(args: list[str]) -> list[str]:
        """Guarantee `log` always runs with `--no-ext-diff --no-textconv`."""
        sub = GitRunner._subcommand(args)
        if sub != "log":
            return args
        missing = [f for f in _LOG_EXTRA_FLAGS if f not in args]
        if not missing:
            return args
        idx = args.index(sub)
        return args[: idx + 1] + missing + args[idx + 1 :]

    def _build_env(self, extra: dict[str, str] | None) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(_BASE_ENV)
        env.update(_ROLE_ENV[self.role])
        if extra:
            env.update(extra)
        return env

    def _raise_for_failure(self, args: list[str], returncode: int, stderr: bytes) -> None:
        message = stderr.decode("utf-8", "replace").strip()
        lowered = message.lower()
        if any(marker in lowered for marker in _UNSAFE_MARKERS):
            raise UnsupportedRepo(message)
        if any(marker in lowered for marker in _NOT_A_REPO_MARKERS):
            raise UnsupportedRepo(message)
        cmd = " ".join(args)
        raise GitError(f"git {cmd} failed (exit {returncode}): {message}")
