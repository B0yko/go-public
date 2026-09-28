"""Squash export (product spec item 14; ADR 0005).

The export repository is assembled directly in its object store, through the `export`
runner only: `init` with an empty template, one `hash-object -w --no-filters --stdin`
per kept blob (metadata already stripped in memory), `update-index --index-info`,
`write-tree`, one `commit-tree` and `update-ref`. Nothing is copied from the source's
object store or config, so nothing the export process did not choose can leak into it:
pre-strip bytes never reach the new object database, no hook or template is inherited,
and the user's own git identity is never consulted (the runner env blocks global and
system config, and the author/committer come only from `--author`/`export.author`).
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unicodedata
from collections import defaultdict, deque
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pathspec

from go_public import scan as scan_mod
from go_public.config import Config
from go_public.detect.files import FilesDetector, check_tracked_config
from go_public.errors import ExportError, GitError, UsageError
from go_public.export import precheck
from go_public.export.strip import strip_bytes
from go_public.git.inventory import build_head_only, repository_roots
from go_public.git.objects import CatFileBatch
from go_public.git.runner import GitRunner
from go_public.model import Finding, severity_rank
from go_public.pipeline import assess
from go_public.report.build import write_reports
from go_public.report.location import resolve_report_dir

_KEPT_MODES = frozenset({b"100644", b"100755", b"120000"})
_SYMLINK_MODE = b"120000"
_GITLINK_MODE = b"160000"
_TRACKED_CONFIG_PATH = ".go-public.toml"
_IDENTITY_RE = re.compile(r"^(?P<name>[^<>\n]+?)\s*<(?P<email>[^<>\n]+)>$")

#: Blob bytes waiting for their `hash-object` writer before the reader pauses.
_MAX_IN_FLIGHT_BYTES = 64 * 1024 * 1024
_WRITER_THREADS = 8
_LISTED_PATH_CAP = 20

Log = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class Identity:
    name: str
    email: str

    @property
    def display(self) -> str:
        return f"{self.name} <{self.email}>"


def parse_identity(text: str, *, what: str = "--author") -> Identity:
    match = _IDENTITY_RE.match(text.strip())
    if match is None:
        raise UsageError(f'{what}: expected "Name <email>", got {text!r}')
    name = match.group("name").strip()
    email = match.group("email").strip()
    if not name or not email:
        raise UsageError(f'{what}: expected "Name <email>", got {text!r}')
    return Identity(name=name, email=email)


def resolve_commit_date(text: str, *, now: datetime | None = None) -> str:
    """`now` or an ISO 8601 timestamp (naive = UTC) as git's `@<epoch> +0000` date."""
    value = text.strip()
    if value.lower() == "now":
        moment = now or datetime.now(UTC)
    else:
        try:
            moment = datetime.fromisoformat(value)
        except ValueError:
            raise UsageError(
                f'--date: expected "now" or an ISO 8601 timestamp, got {text!r}'
            ) from None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
    return f"@{int(moment.timestamp())} +0000"


def validate_out_dir(out: Path, *, source: Path, roots: list[Path]) -> Path:
    """`--out` must not exist or be an empty directory, and must lie outside the source
    repository: the given path, the work tree it belongs to and the git directories
    (`roots`, see `repository_roots`). Returns the resolved path."""
    resolved = out.resolve()
    for protected in {source.resolve(), *roots}:
        if resolved == protected or protected in resolved.parents:
            raise UsageError(f"--out must be outside the source repository: {out}")
    if resolved.exists():
        if not resolved.is_dir():
            raise UsageError(f"--out exists and is not a directory: {out}")
        if any(resolved.iterdir()):
            raise UsageError(f"--out must not exist or be empty: {out}")
    return resolved


@dataclass(frozen=True, slots=True)
class Entry:
    mode: bytes
    oid: str
    path: bytes

    @property
    def text(self) -> str:
        return self.path.decode("utf-8", "surrogateescape")


@dataclass(frozen=True, slots=True)
class Dropped:
    path: str
    reason: str


@dataclass(slots=True)
class Selection:
    kept: list[Entry] = field(default_factory=list)
    dropped: list[Dropped] = field(default_factory=list)


def list_tree(runner: GitRunner, ref: str) -> list[Entry]:
    """Every `ls-tree -r -z` entry at `ref`, paths kept as raw bytes."""
    out = runner.run(["ls-tree", "-r", "-z", "--full-tree", ref])
    entries: list[Entry] = []
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        mode, _otype, oid = meta.split(b" ")
        entries.append(Entry(mode=mode, oid=oid.decode(), path=path))
    return entries


def _unsafe_path(path: str) -> bool:
    parts = path.split("/")
    return any(p in ("", ".", "..") or p.casefold() == ".git" for p in parts)


def select_entries(entries: list[Entry], config: Config, *, auto_exclude: bool) -> Selection:
    """Step 3: keep regular files and symlinks; drop gitlinks, `export.exclude` globs,
    (with auto-exclude) sensitive and internal-notes files, and unsafe paths. The
    tracked-config-with-deny check needs the file's content and is applied when the
    blob is read."""
    exclude_spec = pathspec.PathSpec.from_lines("gitwildmatch", config.export.exclude)
    files = FilesDetector(
        sensitive_files=tuple(config.files.sensitive_files),
        internal_notes=tuple(config.files.internal_notes),
    )
    selection = Selection()
    for entry in entries:
        path = entry.text
        if entry.mode == _GITLINK_MODE:
            selection.dropped.append(Dropped(path, "gitlink"))
        elif entry.mode not in _KEPT_MODES:
            selection.dropped.append(Dropped(path, f"unsupported mode {entry.mode.decode()}"))
        elif _unsafe_path(path):
            selection.dropped.append(Dropped(path, "unsafe path"))
        elif exclude_spec.match_file(path):
            selection.dropped.append(Dropped(path, "export.exclude"))
        elif auto_exclude and files.detect_path(path):
            selection.dropped.append(Dropped(path, "sensitive or internal-notes file"))
        else:
            selection.kept.append(entry)
    return selection


def case_collisions(paths: list[str]) -> list[list[str]]:
    """Groups of two or more distinct paths that differ only in case (or Unicode
    normalisation), which a case-insensitive file system cannot all hold."""
    groups: dict[str, set[str]] = defaultdict(set)
    for path in paths:
        groups[unicodedata.normalize("NFC", path).casefold()].add(path)
    return [sorted(group) for _key, group in sorted(groups.items()) if len(group) > 1]


@dataclass(frozen=True, slots=True)
class SquashRequest:
    source: Path
    out: Path | None
    ref: str
    config: Config
    config_source: str
    scan_options: scan_mod.ScanOptions
    git_version: str
    fail_on: str
    author: Identity | None
    message: str
    commit_date: str
    auto_exclude: bool = True
    strip_metadata: bool = True
    set_identity: bool = True
    force_export: bool = False
    check_only: bool = False
    report_dir: Path | None = None


@dataclass(slots=True)
class SquashResult:
    exit_code: int
    out: Path | None = None
    commit: str | None = None
    tree: str | None = None
    kept: int = 0
    stripped: list[str] = field(default_factory=list)
    dropped: list[Dropped] = field(default_factory=list)
    collisions: list[list[str]] = field(default_factory=list)
    blocking: list[Finding] = field(default_factory=list)
    report_paths: dict[str, Path] = field(default_factory=dict)
    clean: bool | None = None


def describe_finding(finding: Finding) -> str:
    where = finding.location.paths[0] if finding.location.paths else finding.location_key
    return f"[{finding.severity}] {finding.category}/{finding.rule_id} {where}: {finding.preview}"


def run_squash(request: SquashRequest, log: Log) -> SquashResult:
    """Run the squash export (or only its pre-check with `check_only`)."""
    source_runner = GitRunner(request.source, role="source")

    if not request.check_only and request.author is None:
        raise UsageError(
            "no export identity: pass --author 'Name <email>' or set [export] author "
            "(go-public never reads your git config)"
        )
    if not request.check_only and request.out is None:
        raise UsageError("--out is required (unless --check)")
    roots = repository_roots(source_runner)
    out = (
        validate_out_dir(request.out, source=request.source, roots=roots)
        if request.out is not None
        else None
    )
    if out is not None and not request.check_only:
        # Fail before doing any work when the report location would be refused.
        resolve_report_dir(
            repo_name=out.name, scanned_repo=out, override=request.report_dir, protected=roots
        )

    inventory = build_head_only(source_runner, export_ref=request.ref)
    outcome = precheck.run(
        source_runner,
        inventory,
        request.config,
        request.scan_options,
        fail_on=request.fail_on,
        strip_metadata=request.strip_metadata,
        auto_exclude=request.auto_exclude,
    )
    result = SquashResult(exit_code=0, blocking=outcome.blocking)
    if outcome.blocking:
        log(f"pre-check: {len(outcome.blocking)} finding(s) the export cannot resolve:")
        for finding in outcome.blocking:
            log(f"  {describe_finding(finding)}")
        if request.check_only or not request.force_export:
            if not request.check_only:
                log("export refused; fix these, or pass --force-export to override")
            result.exit_code = 1
            return result
        log("--force-export: continuing despite the findings above")
    elif request.check_only:
        log("pre-check: clean")
        return result
    if request.check_only:
        return result

    assert request.author is not None and out is not None  # checked above
    result.out = out
    preexisting = out.exists()
    try:
        _build_export(request, source_runner, out, request.author, result, log)
        _rescan(request, out, request.author, result, log, roots)
    except BaseException:
        _remove_partial(out, keep_dir=preexisting)
        raise
    return result


def _remove_partial(out: Path, *, keep_dir: bool) -> None:
    # `out` was verified empty or absent before anything was written, so everything
    # in it now was written by this run.
    if not out.exists():
        return
    if keep_dir:
        for child in out.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
    else:
        shutil.rmtree(out, ignore_errors=True)


def _build_export(
    request: SquashRequest,
    source_runner: GitRunner,
    out: Path,
    author: Identity,
    result: SquashResult,
    log: Log,
) -> None:
    selection = select_entries(
        list_tree(source_runner, request.ref), request.config, auto_exclude=request.auto_exclude
    )
    out.mkdir(parents=True, exist_ok=True)
    export_runner = GitRunner(out, role="export")
    with tempfile.TemporaryDirectory(prefix="go-public-template-") as template:
        export_runner.run(["init", f"--template={template}", "--initial-branch=main"])
    export_runner.run(["config", "commit.gpgsign", "false"])

    written, stripped, dropped = _write_blobs(request, source_runner, export_runner, selection)
    result.dropped = dropped
    result.stripped = stripped
    result.kept = len(written)

    index_info = b"".join(mode + b" " + oid + b"\t" + path + b"\0" for mode, oid, path in written)
    export_runner.run(
        ["update-index", "-z", "--index-info"],
        input=index_info,
        env={"GIT_INDEX_FILE": str(out / ".git" / "index")},
    )
    tree = export_runner.run(["write-tree"]).decode().strip()
    env = {
        "GIT_AUTHOR_NAME": author.name,
        "GIT_AUTHOR_EMAIL": author.email,
        "GIT_AUTHOR_DATE": request.commit_date,
        "GIT_COMMITTER_NAME": author.name,
        "GIT_COMMITTER_EMAIL": author.email,
        "GIT_COMMITTER_DATE": request.commit_date,
    }
    message = request.message if request.message.endswith("\n") else request.message + "\n"
    commit = (
        export_runner.run(["commit-tree", tree, "-F", "-"], input=message.encode(), env=env)
        .decode()
        .strip()
    )
    # The reflog line records a committer: without the export identity here git would
    # fall back to the OS account name and host name.
    export_runner.run(["update-ref", "refs/heads/main", commit], env=env)
    result.tree = tree
    result.commit = commit

    if written:
        export_runner.run(["checkout", "-f", "HEAD", "--", "."])
    else:
        log("warning: nothing left to export; the commit has an empty tree")

    result.collisions = case_collisions([p.decode("utf-8", "surrogateescape") for *_, p in written])
    for group in result.collisions:
        log(
            "warning: case-collision: "
            + ", ".join(group)
            + " differ only in case; the commit keeps all of them, but a case-insensitive "
            "file system holds only one"
        )

    if request.set_identity:
        export_runner.run(["config", "user.name", author.name])
        export_runner.run(["config", "user.email", author.email])

    log(f"exported {result.kept} file(s) to {out} (commit {commit[:12]})")
    if result.dropped:
        log(f"dropped {len(result.dropped)} path(s) from the export:")
        for item in result.dropped[:_LISTED_PATH_CAP]:
            log(f"  {item.path} ({item.reason})")
        if len(result.dropped) > _LISTED_PATH_CAP:
            log(f"  ... and {len(result.dropped) - _LISTED_PATH_CAP} more")
    if result.stripped:
        log(f"stripped metadata from {len(result.stripped)} file(s)")


def _write_blobs(
    request: SquashRequest,
    source_runner: GitRunner,
    export_runner: GitRunner,
    selection: Selection,
) -> tuple[list[tuple[bytes, bytes, bytes]], list[str], list[Dropped]]:
    """Read each kept blob from the source, strip it in memory and write it into the
    export object store. Returns `(mode, export oid, path)` triples in tree order, the
    paths whose content changed, and every dropped path (content-based drops included)."""
    futures: dict[str, Future[str]] = {}
    changed_sources: set[str] = set()
    plan: list[tuple[Entry, str]] = []  # (entry, key into futures)
    pending: deque[tuple[Future[str], int]] = deque()
    in_flight = 0
    dropped = list(selection.dropped)

    def write_blob(data: bytes) -> str:
        return (
            export_runner.run(["hash-object", "-w", "--no-filters", "--stdin"], input=data)
            .decode()
            .strip()
        )

    with (
        ThreadPoolExecutor(max_workers=_WRITER_THREADS) as pool,
        CatFileBatch(source_runner) as batch,
    ):
        for entry in selection.kept:
            got = batch.get(entry.oid)
            if got is None:
                raise GitError(f"object {entry.oid} for {entry.text} is missing from the source")
            _otype, content = got
            if entry.text == _TRACKED_CONFIG_PATH and check_tracked_config(content) is not None:
                dropped.append(Dropped(entry.text, "tracked go-public config with deny entries"))
                continue
            plan.append((entry, entry.oid))
            if entry.oid in futures:
                continue
            data = content
            if request.strip_metadata and entry.mode != _SYMLINK_MODE:
                try:
                    data = strip_bytes(content)
                except Exception as exc:  # noqa: BLE001 - a stripper bug must not leak the file
                    raise ExportError(
                        f"cannot strip metadata from {entry.text}: {exc} "
                        "(--no-strip exports it unchanged)"
                    ) from exc
            if data != content:
                changed_sources.add(entry.oid)
            future = pool.submit(write_blob, data)
            futures[entry.oid] = future
            pending.append((future, len(data)))
            in_flight += len(data)
            while in_flight > _MAX_IN_FLIGHT_BYTES and pending:
                oldest, size = pending.popleft()
                oldest.result()
                in_flight -= size

    written: list[tuple[bytes, bytes, bytes]] = []
    stripped: list[str] = []
    for entry, key in plan:
        oid = futures[key].result()
        if key not in changed_sources and oid != entry.oid:
            raise ExportError(
                f"blob id of {entry.text} changed during export: {entry.oid} -> {oid}"
            )
        if key in changed_sources:
            stripped.append(entry.text)
        written.append((entry.mode, oid.encode(), entry.path))
    return written, stripped, dropped


def _rescan(
    request: SquashRequest,
    out: Path,
    author: Identity,
    result: SquashResult,
    log: Log,
    source_roots: list[Path],
) -> None:
    """Step 7: re-scan the export, unreachable objects included, with the export
    identity allowed; `NOT CLEAN` keeps the directory and exits 1."""
    config = request.config
    identity_allow = [*config.identity.allow, author.display]
    rescan_config = config.model_copy(
        update={"identity": config.identity.model_copy(update={"allow": identity_allow})}
    )
    options = scan_mod.ScanOptions.from_config(
        rescan_config,
        gitleaks_config=request.scan_options.gitleaks_config,
        jobs=request.scan_options.jobs,
        show_secrets=request.scan_options.show_secrets,
    )
    export_runner = GitRunner(out, role="export")
    assessment = assess(
        export_runner,
        repo_path=out,
        ref="HEAD",
        config=rescan_config,
        config_source=request.config_source,
        options=options,
        git_version=request.git_version,
        fail_on=request.fail_on,
        include_unreachable=True,
    )
    result.report_paths = write_reports(
        assessment.report, out, request.report_dir, protected=source_roots
    )
    log(f"re-scan report: {result.report_paths['json'].parent}")
    if assessment.report.exit_code:
        result.clean = False
        result.exit_code = 1
        remaining = [
            f
            for f in assessment.findings
            if severity_rank(f.severity) >= severity_rank(request.fail_on)
        ]
        log(f"NOT CLEAN: {len(remaining)} finding(s) at or above {request.fail_on} remain")
        for finding in remaining:
            log(f"  {describe_finding(finding)}")
        log(f"the export was kept for inspection: {out}")
        return
    result.clean = True
    log("CLEAN")
    log(
        f"To publish: create an empty repository on your host, then inside {out} run "
        "`git remote add origin <url>` followed by `git push -u origin main`."
    )
