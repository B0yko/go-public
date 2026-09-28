"""The shared detector contract (architecture.md "Scan units and routing").

Every detector implements `detect(text: str, ctx: UnitCtx) -> Iterable[Detection]`.
Only the secrets engine exists yet (stage 2a, `detect/secrets.py`). `TextUnit` and
blob/message routing (magic bytes, NUL/UTF-16 checks, `--jobs` sharding) are the scan
pipeline's job and land in this module in stage 2b; this file only holds the two
dataclasses every detector, including the ones stage 3 adds, is built around.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class UnitCtx:
    """Per-call context a detector needs beyond the text itself.

    `path` and `commit` drive gitleaks-style path- and commit-scoped allowlists and
    path-only rules. Both default to "" for units with no natural path or commit
    (an identity string, a ref name). A blob that occurs at several (path, commit)
    pairs is scanned once per pair by the caller, since path- and commit-dependent
    allowlist decisions can differ per occurrence (architecture.md, stage-2 notes).
    """

    path: str = ""
    commit: str = ""


@dataclass(frozen=True, slots=True)
class Detection:
    """One match, before the scan pipeline (stage 2b) turns it into a
    `model.Finding` (location, fingerprint, group_id, preview, ...).
    """

    category: str
    rule_id: str
    severity: str
    start: int
    end: int
    line: int
    col: int
    value: str
    secret: bool
    extra: dict[str, Any] = field(default_factory=dict)
