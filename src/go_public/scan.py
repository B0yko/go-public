"""Scan orchestration (architecture.md "Data flow" / stage-2.md 2b).

`run()` turns an `Inventory` (stage 1) plus the secrets engine (stage 2a) into a
flat list of `model.Finding`. Blobs are scanned exactly once each (their content is
read from git exactly once, via one `cat-file --batch` per worker) and sharded
across `--jobs` worker processes; commit and tag messages are scanned in the main
process, since they are already in memory from the inventory build and need no
`cat-file` read of their own.

Path- and commit-dependent allowlisting (stage-2.md "Path-dependent parts... must
work with blob-level scanning") is handled by re-running `SecretsEngine.detect()`
once per distinct `(path, commit)` occurrence of a blob rather than once per blob
content: the common case (one blob, one path, one introducing commit) is exactly
"once per blob", and a blob attributed to several (path, commit) pairs is re-matched
once per pair so a rule's own `path` filter and per-occurrence allowlists are each
evaluated against the right path/commit. Detections from different occurrence-runs
of the same blob that share `(rule_id, start)` are the same underlying match (same
content, same offset) and are merged into one finding whose `paths`/`commits` list
only the occurrences where it survived allowlisting — the blob's *content* is still
read from git exactly once (`tests/integration/test_scan_pipeline.py` asserts the
`cat-file` read count, matching the architecture's own wording of that test).

Only the secrets detector exists yet (stage 2a); `detect/pii.py` etc. (stage 3) will
add identity/trailer/ref_name/path units and their own detectors here.
"""

from __future__ import annotations

import multiprocessing
import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from go_public.detect import base
from go_public.detect.base import Detection, UnitCtx
from go_public.detect.gitleaks_config import GitleaksConfig, load_gitleaks_config
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


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Everything `run()` needs beyond the inventory. Picklable: passed straight
    into worker-process initializers when `jobs > 1` (architecture.md: "detectors
    [are] built in the worker initializer from a picklable config").
    """

    gitleaks_config: str | None = None
    generic_entropy: float = 4.3
    generic_detector: bool = True
    max_scan_mb: int = 10
    jobs: int = 0  # 0 = CPU count
    show_secrets: bool = False


def run(
    runner: GitRunner, inventory: Inventory, options: ScanOptions | None = None
) -> list[Finding]:
    """Scan every unique blob plus every commit/tag message; return attributed
    findings. Does not suppress, group into a fix plan, or write a report — those
    are stage 4's `suppress.py`/`plan.py`/`report/*`.
    """
    options = options or ScanOptions()
    config = load_gitleaks_config(options.gitleaks_config)
    engine = SecretsEngine(
        config,
        generic_entropy_threshold=options.generic_entropy,
        generic_detector_enabled=options.generic_detector,
    )

    occ_by_blob = _group_occurrences(inventory)
    tasks = _build_tasks(inventory, occ_by_blob)

    jobs = _resolve_jobs(options.jobs, len(tasks))
    if jobs <= 1:
        rows = _scan_blobs_in_process(runner, engine, tasks, options.max_scan_mb)
    else:
        rows = _scan_blobs_with_pool(runner, tasks, options, jobs)

    for oid, commit_obj in inventory.commits.items():
        rows.extend(_scan_message(engine, commit_obj.message, kind="commit_message", commit=oid))
    for oid, tag_obj in inventory.tags.items():
        rows.extend(_scan_message(engine, tag_obj.message, kind="tag_message", tag=oid))

    return [_finding_from_row(row, inventory, config, options) for row in rows]


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


# -- blob content scanning (shared by in-process and worker-pool paths) ------------


def _scan_blob_content(
    engine: SecretsEngine,
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
            _scan_text_occurrences(
                engine, route.text or "", occ_pairs, kind=base_kind, blob=blob_id
            )
        )
    elif route.kind in base.BINARY_KINDS:
        for field_name, field_text in base.extract_binary_fields(route.kind, content).items():
            rows.extend(
                _scan_text_occurrences(
                    engine,
                    field_text,
                    occ_pairs,
                    kind="binary_field",
                    blob=blob_id,
                    field=field_name,
                )
            )
    # "archive" / "binary" / "large": no text detector runs (stage 3b reports them).
    return rows


def _scan_text_occurrences(
    engine: SecretsEngine,
    text: str,
    occ_pairs: list[_Occurrence],
    *,
    kind: str,
    blob: str,
    field: str | None = None,
) -> list[dict[str, Any]]:
    pairs = occ_pairs or [("", "")]
    # Content matching (keyword prefilter, regex, secretGroup, entropy) runs exactly
    # once here, regardless of how many (path, commit) occurrences this blob/field
    # has; only the path/commit-dependent filtering below re-runs per occurrence
    # (stage-3a fix for the stage-2b per-occurrence deviation; see secrets.py).
    content_scan = engine.scan_content(text)
    merged: dict[tuple[str, int], dict[str, Any]] = {}
    for path, commit in pairs:
        for detection in engine.filter_occurrence(content_scan, UnitCtx(path=path, commit=commit)):
            key = (detection.rule_id, detection.start)
            entry = merged.setdefault(
                key, {"detection": detection, "paths": set(), "commits": set()}
            )
            if path:
                entry["paths"].add(path)
            if commit:
                entry["commits"].add(commit)
    rows: list[dict[str, Any]] = []
    for entry in merged.values():
        matched: Detection = entry["detection"]
        rows.append(
            {
                "kind": kind,
                "blob": blob,
                "field": field,
                "commit": None,
                "tag": None,
                "rule_id": matched.rule_id,
                "category": matched.category,
                "severity": matched.severity,
                "value": matched.value,
                "line": matched.line,
                "col": matched.col,
                "secret": matched.secret,
                "extra": dict(matched.extra),
                "paths": sorted(entry["paths"]),
                "commits": sorted(entry["commits"]),
            }
        )
    return rows


def _scan_message(
    engine: SecretsEngine,
    text: str,
    *,
    kind: str,
    commit: str | None = None,
    tag: str | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ctx = UnitCtx(path="", commit=commit or "")
    content_scan = engine.scan_content(text)
    for detection in engine.filter_occurrence(content_scan, ctx):
        rows.append(
            {
                "kind": kind,
                "blob": None,
                "field": None,
                "commit": commit,
                "tag": tag,
                "rule_id": detection.rule_id,
                "category": detection.category,
                "severity": detection.severity,
                "value": detection.value,
                "line": detection.line,
                "col": detection.col,
                "secret": detection.secret,
                "extra": dict(detection.extra),
                "paths": [],
                "commits": [commit] if commit else [],
            }
        )
    return rows


# -- in-process (--jobs 1, or fewer tasks than workers) -----------------------------


def _scan_blobs_in_process(
    runner: GitRunner, engine: SecretsEngine, tasks: list[_Task], max_scan_mb: int
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
                _scan_blob_content(engine, content, blob_id, pairs, unreachable, max_scan_mb)
            )
    return rows


# -- worker pool (--jobs > 1) --------------------------------------------------------

#: Per-worker-process state, set once by `_pool_init`. Never shared with the main
#: process or between workers; each worker opens its own `cat-file --batch`.
_pool_batch: CatFileBatch | None = None
_pool_engine: SecretsEngine | None = None
_pool_max_scan_mb: int = 10


def _pool_init(
    runner: GitRunner,
    gitleaks_config: str | None,
    generic_entropy: float,
    generic_detector: bool,
    max_scan_mb: int,
) -> None:
    global _pool_batch, _pool_engine, _pool_max_scan_mb
    config = load_gitleaks_config(gitleaks_config)
    _pool_engine = SecretsEngine(
        config, generic_entropy_threshold=generic_entropy, generic_detector_enabled=generic_detector
    )
    _pool_batch = CatFileBatch(runner)
    _pool_batch.__enter__()
    _pool_max_scan_mb = max_scan_mb


def _pool_task(task: _Task) -> list[dict[str, Any]]:
    assert _pool_batch is not None and _pool_engine is not None
    blob_id, pairs, unreachable = task
    got = _pool_batch.get(blob_id)
    if got is None:
        return []
    _obj_type, content = got
    return _scan_blob_content(_pool_engine, content, blob_id, pairs, unreachable, _pool_max_scan_mb)


def _scan_blobs_with_pool(
    runner: GitRunner, tasks: list[_Task], options: ScanOptions, jobs: int
) -> list[dict[str, Any]]:
    ctx = multiprocessing.get_context("spawn")
    initargs = (
        runner,
        options.gitleaks_config,
        options.generic_entropy,
        options.generic_detector,
        options.max_scan_mb,
    )
    rows: list[dict[str, Any]] = []
    with ctx.Pool(processes=jobs, initializer=_pool_init, initargs=initargs) as pool:
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
    raise AssertionError(f"unhandled location kind: {kind!r}")


def _refs_for(row: dict[str, Any], inventory: Inventory) -> list[str]:
    if row["kind"] == "tag_message":
        tag_oid = row["tag"]
        return sorted({ref.name for ref in inventory.refs if ref.target == tag_oid})
    refs: set[str] = set()
    for commit in row["commits"]:
        refs.update(inventory.refs_containing(commit))
    return sorted(refs)


def _present_at_export_ref(row: dict[str, Any], inventory: Inventory) -> bool:
    # Squash export (the default) carries the export ref's current tree forward and
    # nothing else: no history, messages, tags or other refs. Content-bearing kinds
    # (blob/binary_field) are "present" exactly when their blob is still at some path
    # in that tree; every other kind (commit/tag message, and — once stage 3 adds
    # them — identity/trailer/ref_name) is always `False` here. `--keep-history`
    # export's different, message-preserving semantics are stage 4's `plan.py`.
    if row["kind"] in ("blob", "binary_field"):
        return inventory.present_at_export_ref(row["blob"])
    return False


def _title_for(rule_id: str, config: GitleaksConfig) -> str:
    if rule_id == "generic-entropy":
        return "High-entropy value in assignment context"
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
        line=row["line"] if kind != "binary_field" else None,
        column=row["col"] if kind != "binary_field" else None,
        commit=row["commit"] if kind == "commit_message" else None,
        tag=row["tag"] if kind == "tag_message" else None,
        field=row["field"],
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
