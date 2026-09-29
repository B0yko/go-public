"""Scan orchestration.

`run()` turns an `Inventory` plus every detector into a flat list of
`model.Finding`. Blobs are scanned exactly once each (their content is read from git
exactly once, via one `cat-file --batch` per worker) and sharded across `--jobs`
worker processes; commit/tag messages, paths, ref names, identities and trailers are
scanned in the main process, since they are already in memory from the inventory
build and need no extra `cat-file` read.

Path- and commit-dependent allowlisting (only the secrets engine has any) is handled
by scanning a blob/message/field's content exactly once
(`SecretsEngine.scan_content`) and applying the path/commit-dependent decisions once
per `(path, commit)` occurrence afterwards (`SecretsEngine.filter_occurrence`); see
`detect/secrets.py`'s module docstring and `docs/adr/0001-blob-level-scanning.md`.
`detect/pii.py`, `detect/deny.py` and `detect/paths_network.py` have no
path/commit-dependent behaviour at all, so each is simply called once per unit of
text and its result attributed to every occurrence.
"""

from __future__ import annotations

import multiprocessing
import os
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field, replace
from typing import Any

from go_public.config import Config
from go_public.detect import base, commit_meta, files
from go_public.detect import licence as licence_detect
from go_public.detect.base import Detection, UnitCtx
from go_public.detect.deny import DenyDetector
from go_public.detect.files import FilesDetector
from go_public.detect.gitleaks_config import GitleaksConfig, load_gitleaks_config
from go_public.detect.paths_network import PathsNetworkDetector
from go_public.detect.pii import PiiDetector
from go_public.detect.secrets import SecretsEngine, is_lockfile
from go_public.errors import ScanWorkerError
from go_public.git.inventory import BlobOccurrence, Inventory
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
#: `Location.line`/`.column` stay `None`.
_LINE_COL_KINDS = frozenset({"blob", "unreachable_blob", "commit_message", "tag_message"})


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Everything `run()` needs beyond the inventory. Picklable: passed straight
    into worker-process initializers when `jobs > 1`: detectors are built in the worker
    initializer from a picklable config.

    `gitleaks_config`/`generic_entropy`/`generic_detector` mirror `[secrets]` for
    convenience (the CLI can override the gitleaks config path independently of a
    loaded `Config`); every other detector's settings come from `config`.
    `extra_names` is computed by `run()` itself from history when
    `config.pii.detect_names` is set, then threaded through to worker processes,
    since only the main process has the inventory needed to compute it.
    """

    gitleaks_config: str | None = None
    generic_entropy: float = 4.0
    generic_detector: bool = True
    max_scan_mb: int = 10
    jobs: int = 0  # 0 = CPU count
    show_secrets: bool = False
    config: Config = field(default_factory=Config)
    extra_names: tuple[str, ...] = ()

    @classmethod
    def from_config(
        cls,
        config: Config,
        *,
        gitleaks_config: str | None = None,
        jobs: int = 0,
        show_secrets: bool = False,
    ) -> ScanOptions:
        """Options for `config`: an explicit `gitleaks_config` path (the CLI flag)
        wins over `[secrets] gitleaks_config`; `[secrets]` and `[scan]` supply the rest."""
        return cls(
            gitleaks_config=gitleaks_config or config.secrets.gitleaks_config or None,
            generic_entropy=config.secrets.generic_entropy,
            generic_detector=config.secrets.generic_detector,
            max_scan_mb=config.scan.max_scan_mb,
            jobs=jobs or config.scan.jobs,
            show_secrets=show_secrets,
            config=config,
        )


class LicenceNoticeDetector:
    """Thin wrapper around `detect/licence.py`'s stateless `detect_notice`, so it
    slots into `_TextDetectors` like every other per-text detector (no config knobs
    of its own yet). Blob content only: `_scan_message` never calls this, since
    a notice is a fact about a file in history, not about commit-message prose."""

    def detect(self, text: str, *, licence_relevant: bool = False) -> list[Detection]:
        detection = licence_detect.detect_notice(text, licence_relevant=licence_relevant)
        return [detection] if detection is not None else []


@dataclass(frozen=True, slots=True)
class _TextDetectors:
    """Every detector `run()` needs, built once per process (main or worker)."""

    secrets: SecretsEngine
    pii: PiiDetector
    deny: DenyDetector
    paths_network: PathsNetworkDetector
    files: FilesDetector
    licence: LicenceNoticeDetector
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
        licence=LicenceNoticeDetector(),
        gitleaks_config=gitleaks_config,
    )


def detect_secrets_in_text(text: str, path: str, options: ScanOptions) -> list[Detection]:
    """Every secret detection in `text` as if it were the content of `path`, using the
    same engine and settings `run()` uses for blobs (`go-public show`/`redact`)."""
    engine = _build_text_detectors(options).secrets
    return [d for d in engine.detect(text, UnitCtx(path=path)) if d.secret]


def _history_names(config: Config, inventory: Inventory) -> tuple[str, ...]:
    """`--detect-names`: every non-allowlisted identity's name from history,
    deterministic and independent of scan order.
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
    write a report — those are `suppress.py`, `plan.py` and `report/*`.
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
    rows.extend(_scan_identities(detectors.deny, list(config.identity.allow), inventory))
    rows.extend(_scan_trailers(list(config.trailers.flag), inventory))
    rows.extend(_scan_timezones(inventory))
    rows.extend(_scan_tracked_config(inventory, runner))
    rows.extend(_scan_large_files(inventory, config, occ_by_blob))
    rows.extend(_scan_gitlinks(inventory))
    rows.extend(_scan_lfs_pointers(inventory, occ_by_blob))
    rows.extend(_scan_licence_transitions(inventory, runner))
    rows.extend(_scan_licence_head_state(inventory, runner, config))

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
            # is `detect/files.py`'s job. Never scanned as ordinary text.
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


def _is_licence_relevant(occ_pairs: list[_Occurrence]) -> bool:
    """Whether any path this blob's content is known under is licence-relevant
    (`detect/licence.py::is_licence_relevant_path`) — the same blob content can
    legitimately sit at more than one path across history."""
    return any(licence_detect.is_licence_relevant_path(path) for path, _commit in occ_pairs)


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
                licence_relevant=_is_licence_relevant(occ_pairs),
            )
        )
    elif route.kind in base.BINARY_KINDS:
        for bf in base.extract_binary_fields(route.kind, content):
            # go-public's own classification of this field's mere presence
            # (exif-person, ooxml-core, ...), attributed the same way as the text
            # detectors run on its value just below (both happen).
            own = Detection(
                category="binary-metadata",
                rule_id=bf.rule_id,
                severity=bf.severity,
                start=0,
                end=0,
                line=0,
                col=0,
                value=bf.value,
                secret=False,
            )
            rows.extend(
                _scan_unit(
                    detectors,
                    bf.value,
                    occ_pairs,
                    kind="binary_field",
                    blob=blob_id,
                    field_name=bf.name,
                    extra=(own,),
                )
            )
    elif route.kind == "archive":
        detection = Detection(
            category="binary-metadata",
            rule_id="archive-not-scanned",
            severity="info",
            start=0,
            end=0,
            line=0,
            col=0,
            value="archive",
            secret=False,
        )
        rows.extend(_attribute_detections([detection], occ_pairs, kind=base_kind, blob=blob_id))
    # "binary" / "large": no text detector runs.
    return rows


def _attribute_detections(
    detections: list[Detection],
    occ_pairs: list[_Occurrence],
    *,
    kind: str,
    blob: str | None = None,
    field_name: str | None = None,
) -> list[dict[str, Any]]:
    """Attribute detections with no path/commit-dependent behaviour to every
    `(path, commit)` occurrence uniformly."""
    if not detections:
        return []
    pairs = occ_pairs or [("", "")]
    paths = sorted({p for p, _c in pairs if p})
    commits = sorted({c for _p, c in pairs if c})
    return [
        _row(d, kind=kind, blob=blob, field_name=field_name, paths=paths, commits=commits)
        for d in detections
    ]


def _scan_unit(
    detectors: _TextDetectors,
    text: str,
    occ_pairs: list[_Occurrence],
    *,
    kind: str,
    blob: str,
    field_name: str | None = None,
    is_gitmodules: bool = False,
    licence_relevant: bool = False,
    extra: tuple[Detection, ...] = (),
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

    # pii/deny/paths_network/licence-notice have no path/commit-dependent behaviour:
    # run once and attribute the result to every occurrence uniformly, alongside
    # `extra` (the caller's own pre-computed detections, e.g. binary-metadata's
    # field-presence classification).
    pii = detectors.pii.detect(text)
    phones = [d for d in pii if d.rule_id == "pii-phone"]
    stateless = (
        [d for d in pii if d.rule_id != "pii-phone"]
        + detectors.deny.detect(text)
        + detectors.paths_network.detect(text, is_gitmodules=is_gitmodules)
        + detectors.licence.detect(text, licence_relevant=licence_relevant)
        + list(extra)
    )
    rows.extend(
        _attribute_detections(stateless, pairs, kind=kind, blob=blob, field_name=field_name)
    )
    # Phone numbers are not looked for in lockfiles (sizes and counters read as numbers).
    phone_pairs = [(p, c) for p, c in pairs if not is_lockfile(p)]
    if phones and phone_pairs:
        rows.extend(
            _attribute_detections(phones, phone_pairs, kind=kind, blob=blob, field_name=field_name)
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

    # No `detectors.licence.detect(text)` here: `detect_notice`
    # is a fact about a *file* in history, never about commit/tag message prose.
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
    internal-notes globs). Ref names and paths go through deny, and paths also through
    the files and large-file checks."""
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


def _scan_identities(
    deny: DenyDetector, identity_allow: list[str], inventory: Inventory
) -> list[dict[str, Any]]:
    """Identity strings run through the identity check (non-allowlisted only) and
    the deny detector (identity strings never run through the pii or network
    detectors), every distinct identity either way.
    """
    occurrences = commit_meta.collect_identities(inventory.commits, inventory.tags)
    by_identity: dict[str, list[commit_meta.IdentityOccurrence]] = {}
    for occ in occurrences:
        by_identity.setdefault(occ.identity, []).append(occ)

    not_allowed = commit_meta.group_non_allowed_identities(occurrences, identity_allow)

    rows: list[dict[str, Any]] = []
    for identity, occs in by_identity.items():
        commits = sorted({occ.commit for occ in occs if occ.commit})
        if identity in not_allowed:
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
            rows.append(
                _row(detection, kind="identity", identity=identity, paths=[], commits=commits)
            )
        for detection in deny.detect(identity):
            rows.append(
                _row(detection, kind="identity", identity=identity, paths=[], commits=commits)
            )
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
    (the tracked config may only carry allowlists)."""
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


# -- large files / gitlinks / LFS pointers ------------------------------------------

_ONE_MB = 1024 * 1024
_GITHUB_LIMIT_BYTES = 100 * _ONE_MB


def _large_file_tier(size: int, *, warn_mb: int, high_mb: int) -> tuple[str, str] | None:
    """The single highest threshold `size` crosses, or `None` under `warn_mb`. One
    finding per blob rather than up to three duplicates for the same oversized blob."""
    if size >= _GITHUB_LIMIT_BYTES:
        return "large-file-github-limit", "high"
    if size >= high_mb * _ONE_MB:
        return "large-file-high", "medium"
    if size >= warn_mb * _ONE_MB:
        return "large-file-warn", "low"
    return None


def _large_file_row(
    blob_id: str, size: int, tier: tuple[str, str], *, kind: str, **loc: Any
) -> dict[str, Any]:
    rule_id, severity = tier
    detection = Detection(
        category="large-file",
        rule_id=rule_id,
        severity=severity,
        start=0,
        end=0,
        line=0,
        col=0,
        value=str(size),
        secret=False,
        extra={"size_bytes": size},
    )
    return _row(detection, kind=kind, blob=blob_id, **loc)


def _scan_large_files(
    inventory: Inventory, config: Config, occ_by_blob: dict[str, set[_Occurrence]]
) -> list[dict[str, Any]]:
    warn_mb, high_mb = config.files.warn_mb, config.files.high_mb
    rows: list[dict[str, Any]] = []
    for blob_id, size in inventory.blob_sizes.items():
        tier = _large_file_tier(size, warn_mb=warn_mb, high_mb=high_mb)
        if tier is None:
            continue
        pairs = sorted(occ_by_blob.get(blob_id, set()))
        paths = sorted({p for p, _c in pairs if p})
        commits = sorted({c for _p, c in pairs if c})
        rows.append(_large_file_row(blob_id, size, tier, kind="blob", paths=paths, commits=commits))
    for blob_id, size in inventory.unreachable_blobs.items():
        tier = _large_file_tier(size, warn_mb=warn_mb, high_mb=high_mb)
        if tier is None:
            continue
        rows.append(
            _large_file_row(blob_id, size, tier, kind="unreachable_blob", paths=[], commits=[])
        )
    return rows


def _scan_gitlinks(inventory: Inventory) -> list[dict[str, Any]]:
    """Gitlinks (submodules): never exported, never read; one info finding per path."""
    by_path: dict[str, set[str]] = defaultdict(set)
    oid_by_path: dict[str, str] = {}
    for link in inventory.gitlinks:
        by_path[link.path].add(link.commit)
        oid_by_path[link.path] = link.oid
    rows: list[dict[str, Any]] = []
    for path, commits in by_path.items():
        detection = Detection(
            category="large-file",
            rule_id="gitlink",
            severity="info",
            start=0,
            end=0,
            line=0,
            col=0,
            value=path,
            secret=False,
            extra={"oid": oid_by_path[path]},
        )
        rows.append(_row(detection, kind="path", paths=[path], commits=sorted(commits)))
    return rows


def _scan_lfs_pointers(
    inventory: Inventory, occ_by_blob: dict[str, set[_Occurrence]]
) -> list[dict[str, Any]]:
    """LFS pointer blobs: `_build_tasks` never scans their (pointer) text as content
    (an LFS pointer blob yields an info finding only)."""
    rows: list[dict[str, Any]] = []
    for blob_id in inventory.lfs_pointers:
        pairs = sorted(occ_by_blob.get(blob_id, set()))
        paths = sorted({p for p, _c in pairs if p})
        commits = sorted({c for _p, c in pairs if c})
        detection = Detection(
            category="large-file",
            rule_id="lfs-pointer",
            severity="info",
            start=0,
            end=0,
            line=0,
            col=0,
            value=blob_id,
            secret=False,
        )
        rows.append(_row(detection, kind="blob", blob=blob_id, paths=paths, commits=commits))
    return rows


# -- licence history -----------------------------------------------------------------


def _licence_relevant_occurrences(inventory: Inventory) -> dict[str, list[BlobOccurrence]]:
    by_path: dict[str, list[BlobOccurrence]] = defaultdict(list)
    for occ in inventory.occurrences:
        if licence_detect.is_licence_relevant_path(occ.path):
            by_path[occ.path].append(occ)
    return by_path


def _commit_time(inventory: Inventory, commit: str) -> int:
    obj = inventory.commits.get(commit)
    return obj.author.timestamp if obj is not None else 0


def _fetch_blobs(runner: GitRunner, blob_ids: set[str]) -> dict[str, bytes]:
    content_by_blob: dict[str, bytes] = {}
    if not blob_ids:
        return content_by_blob
    with CatFileBatch(runner) as batch:
        for blob_id in blob_ids:
            got = batch.get(blob_id)
            if got is not None:
                content_by_blob[blob_id] = got[1]
    return content_by_blob


def _scan_licence_transitions(inventory: Inventory, runner: GitRunner) -> list[dict[str, Any]]:
    """Each commit that changes a licence file or manifest `license` field, when the
    licence label actually changes (matched by
    `finding.extra["transition_commit"]`, not by location, since two independent
    transitions could carry identical text). Scope: `detect/licence.py`'s own
    docstring explains why an arbitrary file's `SPDX-License-Identifier` header does
    not also feed this."""
    by_path = _licence_relevant_occurrences(inventory)
    if not by_path:
        return []
    needed: set[str] = set()
    for occs in by_path.values():
        for occ in occs:
            needed.add(occ.blob)
            if occ.old_blob:
                needed.add(occ.old_blob)
    content_by_blob = _fetch_blobs(runner, needed)

    rows: list[dict[str, Any]] = []
    for path, occs in by_path.items():
        ordered = sorted(occs, key=lambda o: _commit_time(inventory, o.commit))
        transitions: list[tuple[str, str, str, str]] = []  # (commit, from, to, dst_blob)
        for occ in ordered:
            new_content = content_by_blob.get(occ.blob)
            if new_content is None:
                continue
            to_label = licence_detect.identify_path_content(path, new_content) or "unknown"
            if not occ.old_blob:
                continue  # a brand new file: an initial state, not a transition
            old_content = content_by_blob.get(occ.old_blob)
            if old_content is None:
                continue
            from_label = licence_detect.identify_path_content(path, old_content) or "unknown"
            if from_label != to_label:
                transitions.append((occ.commit, from_label, to_label, occ.blob))
        for index, (commit, from_label, to_label, dst_blob) in enumerate(transitions):
            carried_to = transitions[index + 1][0] if index + 1 < len(transitions) else "HEAD"
            detection = Detection(
                category="licence",
                rule_id="licence-transition",
                severity="medium",
                start=0,
                end=0,
                line=0,
                col=0,
                value=f"{from_label} -> {to_label}",
                secret=False,
                extra={
                    "from": from_label,
                    "to": to_label,
                    "transition_commit": commit,
                    "carried_range": f"{commit}..{carried_to}",
                },
            )
            rows.append(_row(detection, kind="blob", blob=dst_blob, paths=[path], commits=[commit]))
    return rows


def _current_licence_declarations(
    inventory: Inventory, runner: GitRunner
) -> list[tuple[str, str, bytes]]:
    """`(path, label, content)` for every licence-relevant path at the export ref
    that actually declares something (a manifest with no recognisable field yields
    nothing for that path)."""
    relevant = [p for p in inventory.export_tree if licence_detect.is_licence_relevant_path(p)]
    if not relevant:
        return []
    blob_by_path = {p: inventory.export_tree[p][1] for p in relevant}
    content_by_blob = _fetch_blobs(runner, set(blob_by_path.values()))
    results: list[tuple[str, str, bytes]] = []
    for path, blob_id in blob_by_path.items():
        content = content_by_blob.get(blob_id)
        if content is None:
            continue
        label = licence_detect.identify_path_content(path, content)
        if label is not None:
            results.append((path, label, content))
    return results


def _scan_licence_head_state(
    inventory: Inventory, runner: GitRunner, config: Config
) -> list[dict[str, Any]]:
    """`licence-missing-at-head` (no `model.LOCATION_KINDS` fits a whole-repository
    absence check, so this reuses `path` kind with a synthetic repo-root marker path,
    same idea as timezone's reuse of `commit_message`) and
    `licence-foreign-holder` (a licence file's copyright holder vs. `[licence]
    owner`), both read from one export-ref fetch."""
    declarations = _current_licence_declarations(inventory, runner)
    rows: list[dict[str, Any]] = []
    if not declarations:
        detection = Detection(
            category="licence",
            rule_id="licence-missing-at-head",
            severity="info",
            start=0,
            end=0,
            line=0,
            col=0,
            value="",
            secret=False,
        )
        rows.append(_row(detection, kind="path", paths=["."], commits=[]))

    owner = config.licence.owner.strip()
    if owner:
        for path, _label, content in declarations:
            if not licence_detect.is_licence_file_path(path):
                continue
            holder = licence_detect.extract_copyright_holder(
                content.decode("utf-8", errors="replace")
            )
            if holder and owner.lower() not in holder.lower():
                detection = Detection(
                    category="licence",
                    rule_id="licence-foreign-holder",
                    severity="medium",
                    start=0,
                    end=0,
                    line=0,
                    col=0,
                    value=holder,
                    secret=False,
                    extra={"holder": holder, "owner": owner},
                )
                rows.append(_row(detection, kind="path", paths=[path], commits=[]))
    return rows


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
    """Scan blobs in `jobs` spawned workers.

    A `ProcessPoolExecutor` marks itself broken when a worker dies (the initializer
    raised, or the child could not import `__main__`), so a bootstrap failure ends in
    an error instead of an endless respawn loop.
    """
    ctx = multiprocessing.get_context("spawn")
    chunk = max(1, min(64, len(tasks) // (jobs * 8)))
    rows: list[dict[str, Any]] = []
    try:
        with ProcessPoolExecutor(
            max_workers=jobs,
            mp_context=ctx,
            initializer=_pool_init,
            initargs=(runner, options),
        ) as pool:
            for result in pool.map(_pool_task, tasks, chunksize=chunk):
                rows.extend(result)
    except BrokenProcessPool as exc:
        raise ScanWorkerError(
            "a scan worker process died before finishing (it could not start, or it crashed); "
            "re-run with --jobs 1 to scan in the main process"
        ) from exc
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
    # message-preserving semantics are handled in `plan.py`.
    kind = row["kind"]
    if kind in ("blob", "binary_field"):
        # A path-dependent rule (a key-store file name) attributes a blob to the paths it
        # fired on: the blob sitting at HEAD under another name does not make those present.
        paths = row["paths"]
        if paths:
            return any(inventory.export_tree.get(p, ("", ""))[1] == row["blob"] for p in paths)
        return inventory.present_at_export_ref(row["blob"])
    if kind == "path":
        return row["paths"][0] in inventory.export_tree
    return False


#: Human-readable titles for every rule id that isn't a secret rule (those
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
    "exif-gps": "GPS location found in image metadata",
    "exif-person": "Person field found in image metadata",
    "exif-org": "Organisation field found in image metadata",
    "exif-software": "Software field found in image metadata",
    "png-text": "Text metadata found in PNG",
    "png-time": "Time metadata found in PNG",
    "png-exif": "EXIF metadata found in PNG",
    "pdf-info": "PDF Info dictionary field found",
    "pdf-xmp": "PDF XMP metadata field found",
    "ooxml-core": "Office document core property found",
    "ooxml-app": "Office document application property found",
    "ooxml-custom": "Office document custom property found",
    "ooxml-comment-author": "Office document comment author found",
    "ooxml-revision-author": "Office document tracked-change author found",
    "archive-not-scanned": "Archive contents were not scanned",
    "licence-transition": "Licence changed",
    "licence-proprietary": "Proprietary or confidential notice found",
    "licence-foreign-holder": "Copyright holder differs from the configured owner",
    "licence-missing-at-head": "No licence found at the export ref",
    "large-file-warn": "Large blob",
    "large-file-high": "Very large blob",
    "large-file-github-limit": "Blob at or above GitHub's 100 MB push limit",
    "gitlink": "Submodule (gitlink) found",
    "lfs-pointer": "Git LFS pointer found",
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
    finding = Finding(
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
    finding.attach_value(value)
    return finding
