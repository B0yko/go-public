"""The `Finding` and `Report` models (architecture.md "Finding model" / "Report:"),
pydantic v2. `Report.model_json_schema()` is the source of
`schemas/go-public-report-v1.json` (stage-4.md item 11; see `tests/unit/
test_report_schema.py`).
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

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

    # The literal matched text. A private attribute: never part of the model dump, the
    # JSON, the repr or the schema. Only the history-preserving export reads it, to
    # replace exactly the values behind unsuppressed findings.
    _value: str | None = PrivateAttr(default=None)

    @property
    def raw_value(self) -> str | None:
        """The literal text behind this finding when the scan produced it in-process."""
        return self._value

    def attach_value(self, value: str) -> None:
        self._value = value


def repo_display_name(path: str) -> str:
    """A repository's name for the report (product spec item 11: "names the
    repository by its directory name, never by its absolute path"); `.git` is
    stripped so a bare `myrepo.git` reports as `myrepo`, same as a non-bare
    `myrepo/`."""
    name = path.rstrip("/").rsplit("/", 1)[-1]
    return name[: -len(".git")] if name.endswith(".git") and name != ".git" else name


# -- Report (architecture.md "Report:", stage-4.md item 11) ------------------------


class ToolInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "go-public"
    version: str


class RepoInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    bare: bool
    object_format: str
    export_ref: str
    export_commit: str | None = None


class ScanOptionsInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include_unreachable: bool = False
    head_only: bool = False
    fail_on: str = "high"
    jobs: int = 0
    detect_names: bool = False
    show_secrets: bool = False
    config_source: str = "defaults"


class ScanInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    started_at: str
    finished_at: str
    duration_s: float
    git_version: str
    options: ScanOptionsInfo


class InventoryInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refs: int
    commits: int
    tags: int
    unique_blobs: int
    total_bytes: int
    unreachable_blobs: int = 0
    ref_list: list[str] = Field(default_factory=list)
    missing_objects: int = 0
    lfs_pointers: int = 0


class WarningInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str


#: architecture.md "Suppression": every place a finding can be suppressed from.
SUPPRESS_SOURCES: tuple[str, ...] = (
    "config-fingerprint",
    "config-group",
    "path-glob",
    "inline-comment",
    "identity-allow",
)


class SuppressedInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    group_id: str
    category: str
    rule_id: str
    source: str
    reason: str = ""
    pattern: str | None = None


class RotatedInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    reason: str


class PlanEntryA(BaseModel):
    """`plan.py` group A: one row per secret `group_id` (architecture.md "Fix plan")."""

    model_config = ConfigDict(extra="forbid")

    secret_id: str
    rule_id: str
    preview: str
    occurrences: int
    paths: list[str] = Field(default_factory=list)
    commits: list[str] = Field(default_factory=list)
    refs: list[str] = Field(default_factory=list)
    present_at_export_ref: bool
    status: str  # open | rotated
    rotated_reason: str | None = None


class PlanFileGroup(BaseModel):
    """`plan.py` groups B/C: one row per file path, or (`is_path=False`) per location
    kind for non-file items (architecture.md: "grouped per file path (non-file items
    grouped under their kind)")."""

    model_config = ConfigDict(extra="forbid")

    key: str
    is_path: bool
    categories: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)  # fingerprints
    action: str
    fix_text: str = ""


class PlanDecideItem(BaseModel):
    """`plan.py` group D: one row per category (licence, large-file) at the export
    ref (architecture.md: "licence category + large-file findings at the export
    ref")."""

    model_config = ConfigDict(extra="forbid")

    category: str
    findings: list[str] = Field(default_factory=list)  # fingerprints


class PlanModel(BaseModel):
    """architecture.md "Fix plan": `plan{A[], B[], C[], D[], next_commands[]}`.
    `identity_notes` is a stage-4 addition beyond that literal shape (recorded as a
    deviation in STATUS.md): product spec item 12 group D also carries "names if you
    keep history", a plain FYI list of identity strings rather than findings, which
    does not fit `PlanDecideItem`'s per-category/fingerprint shape.
    """

    model_config = ConfigDict(extra="forbid")

    A: list[PlanEntryA] = Field(default_factory=list)
    B: list[PlanFileGroup] = Field(default_factory=list)
    C: list[PlanFileGroup] = Field(default_factory=list)
    D: list[PlanDecideItem] = Field(default_factory=list)
    identity_notes: list[str] = Field(default_factory=list)
    next_commands: list[str] = Field(default_factory=list)


class SummaryInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    by_group: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    blocking: int = 0


class Report(BaseModel):
    """The top-level report object; `report/json.py` writes this straight to JSON,
    and `report/md.py`/`report/html.py` render it. `model_json_schema()` on this
    class is `schemas/go-public-report-v1.json`'s source of truth."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "go-public-report-v1"
    tool: ToolInfo
    repo: RepoInfo
    scan: ScanInfo
    inventory: InventoryInfo
    warnings: list[WarningInfo] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    suppressed: list[SuppressedInfo] = Field(default_factory=list)
    rotated: list[RotatedInfo] = Field(default_factory=list)
    plan: PlanModel
    summary: SummaryInfo
    exit_code: int


def report_json_schema() -> dict[str, object]:
    """`Report.model_json_schema()`, the source of
    `schemas/go-public-report-v1.json` (stage-4.md item 11)."""
    return Report.model_json_schema()
