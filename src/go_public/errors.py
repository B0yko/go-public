"""Exceptions that carry go-public's process exit codes.

Exit codes (architecture.md): 0 clean, 1 findings at or above ``--fail-on``,
2 usage/config error, 3 git error or unsupported repository state.
"""

from __future__ import annotations


class GoPublicError(Exception):
    """Base class for errors the CLI maps to a fixed exit code."""

    exit_code: int = 1


class UsageError(GoPublicError):
    """Bad CLI arguments, or an invalid combination of options."""

    exit_code = 2


class ConfigError(GoPublicError):
    """An invalid, unreadable, or unknown-key configuration file."""

    exit_code = 2


class GitError(GoPublicError):
    """A git subprocess failed for a reason other than an unsupported repo."""

    exit_code = 3


class UnsupportedRepo(GoPublicError):
    """The repository is bare-incompatible, sha256, unsafe, or not a repo at all."""

    exit_code = 3
