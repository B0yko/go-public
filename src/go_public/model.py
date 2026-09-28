"""The `Finding` model (architecture.md "Finding model"), pydantic v2.

Only the `Finding`/`Location`/`FixAction` shapes land in stage 2b: they are what
`scan.py` produces from a `detect.base.Detection` plus attribution. The full
`Report` model (repo/scan/inventory/warnings/suppressed/rotated/plan/summary) and
the generated JSON Schema are stage 4's job (`schemas/go-public-report-v1.json`,
`report/json.py`) — nothing here is a Report field yet.
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field

#: architecture.md "Finding model" Severity enum, ordered least to most severe.
SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

#: architecture.md Category enum (values use hyphens, so this is a plain
#: string-literal set rather than a `StrEnum` with non-identifier members).
CATEGORIES: tuple[str, ...] = (
    "secret",
    "pii",
    "org-identifier",
    "local-path",
    "network",
    "binary-metadata",
    "licence",
    "large-file",
    "sensitive-file",
    "internal-notes",
    "identity",
    "trailer",
    "timezone",
    "config",
)

#: architecture.md LocationKind enum.
LOCATION_KINDS: tuple[str, ...] = (
    "blob",
    "path",
    "commit_message",
    "tag_message",
    "identity",
    "trailer",
    "ref_name",
    "binary_field",
    "unreachable_blob",
)

#: architecture.md FixAction.action enum.
FIX_ACTIONS: tuple[str, ...] = (
    "rotate",
    "edit-line",
    "delete-file",
    "strip",
    "exclude",
    "rename-path",
    "removed-by-squash",
    "review-licence",
    "decide-large-file",
    "rewrite-identity",
    "none",
)

#: Findings at or above this cap keep only the first N commits/refs; `_total` on the
#: finding records the real count. architecture.md: "capped 50" for both lists.
ATTRIBUTION_CAP = 50


def severity_rank(severity: str) -> int:
    """Higher is more severe; used to compare against `--fail-on`."""
    return _SEVERITY_RANK[severity]


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogateescape")).hexdigest()


def make_fingerprint(*, rule_id: str, kind: str, location_key: str, value: str) -> str:
    """`sha256("|".join([rule_id, kind, location_key, sha256(value)]))[:12]`."""
    joined = "|".join([rule_id, kind, location_key, sha256_hex(value)])
    return sha256_hex(joined)[:12]


def make_group_id(*, category: str, rule_id: str, normalized_value: str) -> str:
    """`sha256(f"{category}|{rule_id}|{normalized value}")[:12]`.

    For secrets, `normalized_value` is the secret itself: every finding sharing one
    secret value under one rule id groups into the same fix-plan-A entry.
    """
    return sha256_hex(f"{category}|{rule_id}|{normalized_value}")[:12]


class Location(BaseModel):
    """Where a finding was found. Only the fields relevant to `kind` are set; the
    rest stay `None`/empty, per architecture.md.
    """

    model_config = ConfigDict(extra="forbid")

    kind: str
    blob: str | None = None
    paths: list[str] = Field(default_factory=list)
    line: int | None = None
    column: int | None = None
    commit: str | None = None
    tag: str | None = None
    ref: str | None = None
    field: str | None = None
    identity: str | None = None


class FixAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    text: str = ""


class Finding(BaseModel):
    """One detection, attributed to its commits/refs and ready for the report and
    fix plan (architecture.md "Finding model").
    """

    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    group_id: str
    category: str
    rule_id: str
    severity: str
    title: str
    location: Location
    location_key: str
    commits: list[str] = Field(default_factory=list)
    commits_total: int = 0
    refs: list[str] = Field(default_factory=list)
    refs_total: int = 0
    present_at_export_ref: bool = False
    preview: str = ""
    fix: FixAction
    extra: dict[str, str | int | float | bool | list[str]] = Field(default_factory=dict)
