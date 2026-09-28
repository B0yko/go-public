"""Scan orchestration (architecture.md "Data flow" / stage-2.md 2b, stage-3.md 3a).

`run()` turns an `Inventory` (stage 1) plus every detector into a flat list of
`model.Finding`. Blobs are scanned exactly once each (their content is read from git
exactly once, via one `cat-file --batch` per worker) and sharded across `--jobs`
worker processes; commit/tag messages, paths, ref names, identities and trailers are
scanned in the main process, since they are already in memory from the inventory
build and need no extra `cat-file` read.

Path- and commit-dependent allowlisting (only the secrets engine has any) is handled
by scanning a blob/message/field's content exactly once
(`SecretsEngine.scan_content`) and applying the path/commit-dependent decisions once
per `(path, commit)` occurrence afterwards (`SecretsEngine.filter_occurrence`); see
`detect/secrets.py`'s module docstring and STATUS.md for the stage-2b deviation this
fixes. `detect/pii.py`, `detect/deny.py` and `detect/paths_network.py` have no
path/commit-dependent behaviour at all, so each is simply called once per unit of
text and its result attributed to every occurrence.
"""

from __future__ import annotations

import multiprocessing
import os
from collections import defaultdict
from dataclasses import dataclass, field, replace
from typing import Any

from go_public.config import Config
from go_public.detect import base, commit_meta, files
from go_public.detect.base import Detection, UnitCtx
from go_public.detect.deny import DenyDetector
from go_public.detect.files import FilesDetector
from go_public.detect.gitleaks_config import GitleaksConfig, load_gitleaks_config
from go_public.detect.paths_network import PathsNetworkDetector
from go_public.detect.pii import PiiDetector
from go_public.detect.secrets import SecretsEngine
from go_public.git.inventory import Inventory
from go_public.git.objects import CatFileBatch
from go_public.git.runner import GitRunner
from go_public.model import (
    ATTRIBUTION_CAP,
    Finding,
    FixAction,
    Location,
    make_fingerprint,
    make_group_id,
)
from go_public.redaction import make_preview

_Occurrence = tuple[str, str]  # (path, commit); "" for "no path"/"no commit"
_Task = tuple[str, list[_Occurrence], bool]  # (blob_id, occurrence pairs, unreachable)

#: Location kinds whose `line`/`col` are meaningful text offsets; every other kind's
#: `Location.line`/`.column` stay `None` (architecture.md "Finding model").
_LINE_COL_KINDS = frozenset({"blob", "unreachable_blob", "commit_message", "tag_message"})


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Everything `run()` needs beyond the inventory. Picklable: passed straight
    into worker-process initializers when `jobs > 1` (architecture.md: "detectors
    [are] built in the worker initializer from a picklable config").

    `gitleaks_config`/`generic_entropy`/`generic_detector` mirror `[secrets]` for
    convenience (the CLI can override the gitleaks config path independently of a
    loaded `Config`); every other detector's settings come from `config`.
    `extra_names` is computed by `run()` itself from history when
    `config.pii.detect_names` is set, then threaded through to worker processes,
    since only the main process has the inventory needed to compute it.
    """

    gitleaks_config: str | None = None
    generic_entropy: float = 4.3
    generic_detector: bool = True
    max_scan_mb: int = 10
    jobs: int = 0  # 0 = CPU count
    show_secrets: bool = False
    config: Config = field(default_factory=Config)
    extra_names: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _TextDetectors:
    """Every detector `run()` needs, built once per process (main or worker)."""

    secrets: SecretsEngine
    pii: PiiDetector
    deny: DenyDetector
    paths_network: PathsNetworkDetector
    files: FilesDetector
    gitleaks_config: GitleaksConfig


def _build_text_detectors(options: ScanOptions) -> _TextDetectors:
    gitleaks_config = load_gitleaks_config(options.gitleaks_config)
    config = options.config
    names = frozenset(config.deny.names) | frozenset(options.extra_names)
    return _TextDetectors(
        secrets=SecretsEngine(
            gitleaks_config,
            generic_entropy_threshold=options.generic_entropy,
            generic_detector_enabled=options.generic_detector,
        ),
        pii=PiiDetector(
            phone_regions=tuple(config.pii.phone_regions),
            identity_allow=tuple(config.identity.allow),
            names=names,
        ),
        deny=DenyDetector(
            terms=tuple(config.deny.terms),
            domains=tuple(config.deny.domains),
            regexes=tuple(config.deny.regex),
            ticket_keys=tuple(config.deny.ticket_keys),
        ),
        paths_network=PathsNetworkDetector(
            allowed_path_prefixes=tuple(config.paths.allowed_prefixes),
            internal_suffixes=tuple(config.network.internal_suffixes),
            deny_domains=tuple(config.deny.domains),
        ),
        files=FilesDetector(
            sensitive_files=tuple(config.files.sensitive_files),
            internal_notes=tuple(config.files.internal_notes),
        ),
        gitleaks_config=gitleaks_config,
    )


def _history_names(config: Config, inventory: Inventory) -> tuple[str, ...]:
    """`--detect-names`: every non-allowlisted identity's name from history
    (product spec item 3), deterministic and independent of scan order.
    """
    occurrences = commit_meta.collect_identities(inventory.commits, inventory.tags)
    grouped = commit_meta.group_non_allowed_identities(occurrences, list(config.identity.allow))
    names = {identity.split(" <", 1)[0] for identity in grouped if identity.split(" <", 1)[0]}
    return tuple(sorted(names))


def _resolve_options(options: ScanOptions, inventory: Inventory) -> ScanOptions:
    if not options.config.pii.detect_names or options.extra_names:
        return options
    return replace(options, extra_names=_history_names(options.config, inventory))


def run(
    runner: GitRunner, inventory: Inventory, options: ScanOptions | None = None
) -> list[Finding]:
    """Scan every unique blob, commit/tag message, path, ref name, identity and
    trailer; return attributed findings. Does not suppress, group into a fix plan, or
    write a report — those are stage 4's `suppress.py`/`plan.py`/`report/*`.
    """
    options = _resolve_options(options or ScanOptions(), inventory)
    detectors = _build_text_detectors(options)
    config = options.config

    occ_by_blob = _group_occurrences(inventory)
    tasks = _build_tasks(inventory, occ_by_blob)

    jobs = _resolve_jobs(options.jobs, len(tasks))
    if jobs <= 1:
        rows = _scan_blobs_in_process(runner, detectors, tasks, options.max_scan_mb)
    else:
        rows = _scan_blobs_with_pool(runner, tasks, options, jobs)

    for oid, commit_obj in inventory.commits.items():
        rows.extend(_scan_message(detectors, commit_obj.message, kind="commit_message", commit=oid))
    for oid, tag_obj in inventory.tags.items():
        rows.extend(_scan_message(detectors, tag_obj.message, kind="tag_message", tag=oid))

    rows.extend(_scan_paths(detectors.deny, detectors.files, inventory))
    rows.extend(_scan_ref_names(detectors.deny, inventory))
    rows.extend(_scan_identities(list(config.identity.allow), inventory))
    rows.extend(_scan_trailers(list(config.trailers.flag), inventory))
    rows.extend(_scan_timezones(inventory))
    rows.extend(_scan_tracked_config(inventory, runner))

    return [_finding_from_row(row, inventory, detectors.gitleaks_config, options) for row in rows]


# -- blob grouping / task building -------------------------------------------------


def _group_occurrences(inventory: Inventory) -> dict[str, set[_Occurrence]]:
    occ_by_blob: dict[str, set[_Occurrence]] = defaultdict(set)
    for occ in inventory.occurrences:
        occ_by_blob[occ.blob].add((occ.path, occ.commit))
    if inventory.head_only:
        # `--head-only` never populates `occurrences` (no history pass); the export
        # tree is the only source of (blob, path) pairs, and there is no commit
        # context to attach.
        for path, (_mode, blob) in inventory.export_tree.items():
            occ_by_blob[blob].add((path, ""))
    return occ_by_blob


def _build_tasks(inventory: Inventory, occ_by_blob: dict[str, set[_Occurrence]]) -> list[_Task]:
    tasks: list[_Task] = []
    for blob_id in inventory.blob_sizes:
        if blob_id in inventory.lfs_pointers:
            # Content is just the pointer text; the real "lfs-pointer" info finding
            # is stage 3b's `detect/files.py` job. Never scanned as ordinary text.
            continue
        pairs = sorted(occ_by_blob.get(blob_id, set()))
        tasks.append((blob_id, pairs, False))
    for blob_id in inventory.unreachable_blobs:
        tasks.append((blob_id, [], True))
    return tasks


def _resolve_jobs(jobs: int, task_count: int) -> int:
    resolved = jobs if jobs > 0 else (os.cpu_count() or 1)
    return max(1, min(resolved, task_count)) if task_count else 1


def _is_gitmodules(occ_pairs: list[_Occurrence]) -> bool:
    return any(path.rsplit("/", 1)[-1] == ".gitmodules" for path, _commit in occ_pairs)


# -- row builders --------------------------------------------------------------------


def _row(
    detection: Detection,
    *,
    kind: str,
    blob: str | None = None,
    field_name: str | None = None,
    commit: str | None = None,
    tag: str | None = None,
    ref: str | None = None,
    identity: str | None = None,
    paths: list[str],
    commits: list[str],
) -> dict[str, Any]:
    return {
        "kind": kind,
        "blob": blob,
        "field": field_name,
        "commit": commit,
        "tag": tag,
        "ref": ref,
        "identity": identity,
        "rule_id": detection.rule_id,
        "category": detection.category,
        "severity": detection.severity,
        "value": detection.value,
        "line": detection.line,
        "col": detection.col,
        "secret": detection.secret,
        "extra": dict(detection.extra),
        "paths": paths,
        "commits": commits,
    }


# -- blob content scanning (shared by in-process and worker-pool paths) ------------


def _scan_blob_content(
    detectors: _TextDetectors,
    content: bytes,
    blob_id: str,
    occ_pairs: list[_Occurrence],
    unreachable: bool,
    max_scan_mb: int,
) -> list[dict[str, Any]]:
    route = base.route_blob(content, max_scan_mb=max_scan_mb)
    base_kind = "unreachable_blob" if unreachable else "blob"
    rows: list[dict[str, Any]] = []
    if route.kind == "text":
        rows.extend(
            _scan_unit(
                detectors,
                route.text or "",
                occ_pairs,
                kind=base_kind,
                blob=blob_id,
                is_gitmodules=_is_gitmodules(occ_pairs),
            )
        )
    elif route.kind in base.BINARY_KINDS:
        for field_name, field_text in base.extract_binary_fields(route.kind, content).items():
            rows.extend(
                _scan_unit(
                    detectors,
                    field_text,
                    occ_pairs,
                    kind="binary_field",
                    blob=blob_id,
                    field_name=field_name,
                )
            )
    # "archive" / "binary" / "large": no text detector runs (stage 3b reports them).
    return rows


def _scan_unit(
    detectors: _TextDetectors,
    text: str,
    occ_pairs: list[_Occurrence],
    *,
    kind: str,
    blob: str,
    field_name: str | None = None,
    is_gitmodules: bool = False,
) -> list[dict[str, Any]]:
    """Run every text detector over one blob/binary-field's content, attributing the
    result to every `(path, commit)` occurrence this blob/field has.
    """
    pairs = occ_pairs or [("", "")]
    rows: list[dict[str, Any]] = []

    # Secrets: content matched exactly once (`scan_content`); the global/per-rule
    # allowlists and a rule's own `path` are then applied once per occurrence
    # (`filter_occurrence`), and detections that land on the same `(rule_id, start)`
    # across occurrences are the same match and are merged.
    content_scan = detectors.secrets.scan_content(text)
    merged: dict[tuple[str, int], dict[str, Any]] = {}
    for path, commit in pairs:
        for detection in detectors.secrets.filter_occurrence(
            content_scan, UnitCtx(path=path, commit=commit)
        ):
            key = (detection.rule_id, detection.start)
            entry = merged.setdefault(
                key, {"detection": detection, "paths": set(), "commits": set()}
            )
            if path:
                entry["paths"].add(path)
            if commit:
                entry["commits"].add(commit)
    for entry in merged.values():
        rows.append(
            _row(
                entry["detection"],
                kind=kind,
                blob=blob,
                field_name=field_name,
                paths=sorted(entry["paths"]),
                commits=sorted(entry["commits"]),
            )
        )

    # pii/deny/paths_network have no path/commit-dependent behaviour: run once and
    # attribute the result to every occurrence uniformly.
    stateless = (
        detectors.pii.detect(text)
        + detectors.deny.detect(text)
        + detectors.paths_network.detect(text, is_gitmodules=is_gitmodules)
    )
    if stateless:
        paths = sorted({p for p, _c in pairs if p})
        commits = sorted({c for _p, c in pairs if c})
        for detection in stateless:
            rows.append(
                _row(
                    detection,
                    kind=kind,
                    blob=blob,
                    field_name=field_name,
                    paths=paths,
                    commits=commits,
                )
            )
    return rows


def _scan_message(
    detectors: _TextDetectors,
    text: str,
    *,
    kind: str,
    commit: str | None = None,
    tag: str | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ctx = UnitCtx(path="", commit=commit or "")
    content_scan = detectors.secrets.scan_content(text)
    commits = [commit] if commit else []
    for detection in detectors.secrets.filter_occurrence(content_scan, ctx):
        rows.append(_row(detection, kind=kind, commit=commit, tag=tag, paths=[], commits=commits))

    stateless = (
        detectors.pii.detect(text)
        + detectors.deny.detect(text)
        + detectors.paths_network.detect(text)
    )
    for detection in stateless:
        rows.append(_row(detection, kind=kind, commit=commit, tag=tag, paths=[], commits=commits))
    return rows


# -- path / ref-name / identity / trailer / timezone / tracked-config units --------


def _paths_with_commits(inventory: Inventory) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for occ in inventory.occurrences:
        result[occ.path].add(occ.commit)
    if inventory.head_only:
        for path in inventory.export_tree:
            result.setdefault(path, set())
    return result


def _scan_paths(
    deny: DenyDetector, files_detector: FilesDetector, inventory: Inventory
) -> list[dict[str, Any]]:
    """Every unique path through deny (org identifiers) and files (sensitive/
    internal-notes globs) — architecture.md: "Ref names and paths through deny (and
    files/large detectors for paths)."""
    rows: list[dict[str, Any]] = []
    for path, commits in _paths_with_commits(inventory).items():
        detections = deny.detect(path) + files_detector.detect_path(path)
        for detection in detections:
            rows.append(_row(detection, kind="path", paths=[path], commits=sorted(commits)))
    return rows


def _scan_ref_names(deny: DenyDetector, inventory: Inventory) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ref in inventory.refs:
        for detection in deny.detect(ref.name):
            rows.append(_row(detection, kind="ref_name", ref=ref.name, paths=[], commits=[]))
    return rows


def _scan_identities(identity_allow: list[str], inventory: Inventory) -> list[dict[str, Any]]:
    occurrences = commit_meta.collect_identities(inventory.commits, inventory.tags)
    grouped = commit_meta.group_non_allowed_identities(occurrences, identity_allow)
    rows: list[dict[str, Any]] = []
    for identity, occs in grouped.items():
        commits = sorted({occ.commit for occ in occs if occ.commit})
        roles = sorted({occ.role for occ in occs})
        detection = Detection(
            category="identity",
            rule_id="identity",
            severity="medium",
            start=0,
            end=0,
            line=0,
            col=0,
            value=identity,
            secret=False,
            extra={"roles": roles},
        )
        rows.append(_row(detection, kind="identity", identity=identity, paths=[], commits=commits))
    return rows


def _scan_trailers(flagged_keys: list[str], inventory: Inventory) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for trailer in commit_meta.collect_trailers(inventory.commits, flagged_keys):
        severity = commit_meta.trailer_severity(trailer.value)
        detection = Detection(
            category="trailer",
            rule_id="trailer",
            severity=severity,
            start=0,
            end=0,
            line=0,
            col=0,
            value=trailer.value,
            secret=False,
        )
        rows.append(
            _row(
                detection,
                kind="trailer",
                field_name=trailer.key,
                commit=trailer.commit,
                paths=[],
                commits=[trailer.commit],
            )
        )
    return rows


def _scan_timezones(inventory: Inventory) -> list[dict[str, Any]]:
    """Non-UTC offsets, attached to the `commit_message` location kind (there is no
    dedicated "commit" kind in `model.LOCATION_KINDS`); `col` distinguishes the
    author/committer roles of one commit so their location keys never collide.
    """
    rows: list[dict[str, Any]] = []
    for offset in commit_meta.collect_timezone_offsets(inventory.commits):
        col = 1 if offset.role == "author" else 2
        detection = Detection(
            category="timezone",
            rule_id="timezone-offset",
            severity="info",
            start=0,
            end=0,
            line=0,
            col=col,
            value=offset.tz,
            secret=False,
            extra={"role": offset.role},
        )
        rows.append(
            _row(
                detection,
                kind="commit_message",
                commit=offset.commit,
                paths=[],
                commits=[offset.commit],
            )
        )
    return rows


def _scan_tracked_config(inventory: Inventory, runner: GitRunner) -> list[dict[str, Any]]:
    """A tracked `.go-public.toml` at the export ref with a non-empty `[deny]` table
    (architecture.md "Config" discovery order)."""
    entry = inventory.export_tree.get(".go-public.toml")
    if entry is None:
        return []
    _mode, blob = entry
    with CatFileBatch(runner) as batch:
        got = batch.get(blob)
    if got is None:
        return []
    _obj_type, content = got
    detection = files.check_tracked_config(content)
    if detection is None:
        return []
    return [_row(detection, kind="path", paths=[".go-public.toml"], commits=[])]


# -- in-process (--jobs 1, or fewer tasks than workers) -----------------------------


def _scan_blobs_in_process(
    runner: GitRunner, detectors: _TextDetectors, tasks: list[_Task], max_scan_mb: int
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not tasks:
        return rows
    with CatFileBatch(runner) as batch:
        for blob_id, pairs, unreachable in tasks:
            got = batch.get(blob_id)
            if got is None:
                continue
            _obj_type, content = got
            rows.extend(
                _scan_blob_content(detectors, content, blob_id, pairs, unreachable, max_scan_mb)
            )
    return rows


# -- worker pool (--jobs > 1) --------------------------------------------------------

#: Per-worker-process state, set once by `_pool_init`. Never shared with the main
#: process or between workers; each worker opens its own `cat-file --batch`.
_pool_batch: CatFileBatch | None = None
_pool_detectors: _TextDetectors | None = None
_pool_max_scan_mb: int = 10


def _pool_init(runner: GitRunner, options: ScanOptions) -> None:
    global _pool_batch, _pool_detectors, _pool_max_scan_mb
    _pool_detectors = _build_text_detectors(options)
    _pool_batch = CatFileBatch(runner)
    _pool_batch.__enter__()
    _pool_max_scan_mb = options.max_scan_mb


def _pool_task(task: _Task) -> list[dict[str, Any]]:
    assert _pool_batch is not None and _pool_detectors is not None
    blob_id, pairs, unreachable = task
    got = _pool_batch.get(blob_id)
    if got is None:
        return []
    _obj_type, content = got
    return _scan_blob_content(
        _pool_detectors, content, blob_id, pairs, unreachable, _pool_max_scan_mb
    )


def _scan_blobs_with_pool(
    runner: GitRunner, tasks: list[_Task], options: ScanOptions, jobs: int
) -> list[dict[str, Any]]:
    ctx = multiprocessing.get_context("spawn")
    rows: list[dict[str, Any]] = []
    with ctx.Pool(processes=jobs, initializer=_pool_init, initargs=(runner, options)) as pool:
        for result in pool.map(_pool_task, tasks):
            rows.extend(result)
    return rows


# -- rows -> Finding ------------------------------------------------------------------


def _location_key(row: dict[str, Any]) -> str:
    kind = row["kind"]
    if kind == "binary_field":
        return f"{row['blob']}:{row['field']}"
    if kind in ("blob", "unreachable_blob"):
        return f"{row['blob']}:{row['line']}:{row['col']}"
    if kind == "commit_message":
        return f"{row['commit']}:{row['line']}:{row['col']}"
    if kind == "tag_message":
        return f"{row['tag']}:{row['line']}:{row['col']}"
    if kind == "identity":
        return str(row["identity"])
    if kind == "trailer":
        return f"{row['commit']}:{row['field'].lower()}:{row['value']}"
    if kind == "ref_name":
        return str(row["ref"])
    if kind == "path":
        return str(row["paths"][0])
    raise AssertionError(f"unhandled location kind: {kind!r}")


def _refs_for(row: dict[str, Any], inventory: Inventory) -> list[str]:
    if row["kind"] == "tag_message":
        tag_oid = row["tag"]
        return sorted({ref.name for ref in inventory.refs if ref.target == tag_oid})
    if row["kind"] == "ref_name":
        return [row["ref"]]
    refs: set[str] = set()
    for commit in row["commits"]:
        refs.update(inventory.refs_containing(commit))
    return sorted(refs)


def _present_at_export_ref(row: dict[str, Any], inventory: Inventory) -> bool:
    # Squash export (the default) carries the export ref's current tree forward and
    # nothing else: no history, messages, tags, identities, trailers or other refs.
    # Content-bearing kinds (blob/binary_field) are "present" exactly when their blob
    # is still at some path in that tree; a path-kind finding is present exactly when
    # that path is still in the tree. `--keep-history` export's different,
    # message-preserving semantics are stage 4's `plan.py`.
    kind = row["kind"]
    if kind in ("blob", "binary_field"):
        return inventory.present_at_export_ref(row["blob"])
    if kind == "path":
        return row["paths"][0] in inventory.export_tree
    return False


#: Human-readable titles for every stage-3 rule id that isn't a secret rule (those
#: come from the gitleaks config's own `description`, via `_title_for`).
_TITLES: dict[str, str] = {
    "pii-email": "Email address found in content",
    "pii-phone": "Phone number found in content",
    "pii-name": "A flagged name was found in content",
    "deny-term": "Deny-listed organisation term found",
    "deny-domain": "Deny-listed domain found",
    "deny-regex": "Deny-listed pattern found",
    "deny-ticket": "Deny-listed ticket key found",
    "user-path": "Local path reveals a username",
    "macos-temp-path": "macOS per-user temp path found",
    "private-ip": "Private IP address found",
    "internal-host": "Internal hostname found",
    "private-submodule-url": ".gitmodules URL points at a private host",
    "sensitive-file": "Sensitive file tracked in history",
    "internal-notes": "Internal-notes file tracked in history",
    "identity": "Identity not on the allowlist",
    "trailer": "Flagged commit trailer",
    "timezone-offset": "Non-UTC commit timestamp",
    "tracked-config-deny": "Tracked .go-public.toml has a non-empty [deny] table",
}


def _title_for(rule_id: str, config: GitleaksConfig) -> str:
    if rule_id == "generic-entropy":
        return "High-entropy value in assignment context"
    title = _TITLES.get(rule_id)
    if title is not None:
        return title
    rule = config.rules.get(rule_id)
    if rule is not None and rule.description:
        return rule.description
    return f"Secret detected: {rule_id}"


def _fix_for(row: dict[str, Any]) -> FixAction:
    if row["secret"]:
        return FixAction(action="rotate", text="Rotate this secret, then remove it from history.")
    return FixAction(action="none")


def _finding_from_row(
    row: dict[str, Any], inventory: Inventory, config: GitleaksConfig, options: ScanOptions
) -> Finding:
    kind = row["kind"]
    location_key = _location_key(row)
    location = Location(
        kind=kind,
        blob=row["blob"],
        paths=row["paths"],
        line=row["line"] if kind in _LINE_COL_KINDS else None,
        column=row["col"] if kind in _LINE_COL_KINDS else None,
        commit=row["commit"] if kind in ("commit_message", "trailer") else None,
        tag=row["tag"] if kind == "tag_message" else None,
        ref=row["ref"],
        field=row["field"],
        identity=row["identity"],
    )
    commits: list[str] = row["commits"]
    refs = _refs_for(row, inventory)
    value = row["value"]
    return Finding(
        fingerprint=make_fingerprint(
            rule_id=row["rule_id"], kind=kind, location_key=location_key, value=value
        ),
        group_id=make_group_id(
            category=row["category"], rule_id=row["rule_id"], normalized_value=value
        ),
        category=row["category"],
        rule_id=row["rule_id"],
        severity=row["severity"],
        title=_title_for(row["rule_id"], config),
        location=location,
        location_key=location_key,
        commits=commits[:ATTRIBUTION_CAP],
        commits_total=len(commits),
        refs=refs[:ATTRIBUTION_CAP],
        refs_total=len(refs),
        present_at_export_ref=_present_at_export_ref(row, inventory),
        preview=make_preview(value, secret=row["secret"], show_secrets=options.show_secrets),
        fix=_fix_for(row),
        extra=row["extra"],
    )
