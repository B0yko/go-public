"""Sensitive and internal-notes files, matched by name, and the
tracked-`.go-public.toml`-with-a-deny-list check.
"""

from __future__ import annotations

import tomllib

import pathspec

from go_public.detect.base import Detection

#: Patterns considered private keys or `.env` files (critical); every other
#: `[files] sensitive_files` match is "other sensitive files" (high).
_CRITICAL_SENSITIVE_PATTERNS = ("id_rsa*", "*.pem", "*.key", "*.p12", "*.pfx", ".env", ".env.*")

_DENY_TABLE_KEYS = ("terms", "domains", "regex", "names", "ticket_keys")


class FilesDetector:
    """`sensitive_files`/`internal_notes` glob matching over every unique path."""

    def __init__(
        self,
        *,
        sensitive_files: tuple[str, ...] = (),
        internal_notes: tuple[str, ...] = (),
    ) -> None:
        self._sensitive_spec = pathspec.PathSpec.from_lines("gitwildmatch", sensitive_files)
        self._internal_spec = pathspec.PathSpec.from_lines("gitwildmatch", internal_notes)
        self._critical_spec = pathspec.PathSpec.from_lines(
            "gitwildmatch", _CRITICAL_SENSITIVE_PATTERNS
        )

    def detect_path(self, path: str) -> list[Detection]:
        out: list[Detection] = []
        if self._sensitive_spec.match_file(path):
            severity = "critical" if self._critical_spec.match_file(path) else "high"
            out.append(
                Detection(
                    category="sensitive-file",
                    rule_id="sensitive-file",
                    severity=severity,
                    start=0,
                    end=0,
                    line=0,
                    col=0,
                    value=path,
                    secret=False,
                )
            )
        if self._internal_spec.match_file(path):
            out.append(
                Detection(
                    category="internal-notes",
                    rule_id="internal-notes",
                    severity="medium",
                    start=0,
                    end=0,
                    line=0,
                    col=0,
                    value=path,
                    secret=False,
                )
            )
        return out


def check_tracked_config(content: bytes) -> Detection | None:
    """A tracked `.go-public.toml` at the export ref with a non-empty `[deny]` table
    is a critical `tracked-config-deny` finding (category `config`): the repository
    would ship a deny-list the export process could otherwise strip content by, but
    which stays visible to anyone reading the published config.
    """
    try:
        data = tomllib.loads(content.decode("utf-8", errors="replace"))
    except tomllib.TOMLDecodeError:
        return None
    deny = data.get("deny")
    if not isinstance(deny, dict):
        return None
    if not any(deny.get(key) for key in _DENY_TABLE_KEYS):
        return None
    return Detection(
        category="config",
        rule_id="tracked-config-deny",
        severity="critical",
        start=0,
        end=0,
        line=0,
        col=0,
        value=".go-public.toml",
        secret=False,
    )
