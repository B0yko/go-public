"""History-preserving export (ADR 0007).

`--keep-history` clones the export ref's branch into `--out` through the `export` runner
(`clone --no-local --single-branch --branch <b>`, no checkout, an empty template),
detaches the clone from its origin, renames the branch to `main` and rewrites every
commit with git-filter-repo run as a library in a child process (`_filter_child.py`).
That child is the only git access outside `GitRunner`. The pre-check, the re-scan and
the exit decision follow the squash export; licence history is listed under group D and
does not decide the outcome unless `--fail-on-licence` is given.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pathspec

from go_public import scan as scan_mod
from go_public.config import Config
from go_public.detect.files import FilesDetector
from go_public.errors import ExportError, GitError, UsageError
from go_public.export import precheck
from go_public.export._filter_child import SPEC_VERSION, STATS_PREFIX
from go_public.export.squash import (
    Identity,
    SquashResult,
    describe_finding,
    remove_partial,
    rescan_export,
    validate_out_dir,
)
from go_public.git.inventory import Inventory, build, build_head_only, repository_roots
from go_public.git.runner import GitRunner
from go_public.model import Finding
from go_public.report.location import resolve_report_dir

REMOVED = "***REMOVED***"

#: Findings whose literal text is replaced in blobs and messages. Paths, identities,
#: ref names and binary metadata have their own handling; licence text stays as written.
_REPLACED_CATEGORIES = frozenset({"secret", "pii", "org-identifier", "local-path", "network"})
_REPLACED_KINDS = frozenset({"blob", "commit_message", "tag_message"})
_TRACKED_CONFIG_PATH = ".go-public.toml"
_ONE_MB = 1024 * 1024
_FALLBACK_IDENTITY = Identity(name="go-public", email="go-public@example.invalid")
_STDERR_TAIL = 15

Log = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class HistoryRequest:
    source: Path
    out: Path | None
    ref: str
    config: Config
    config_source: str
    scan_options: scan_mod.ScanOptions
    git_version: str
    fail_on: str
    author: Identity | None
    mailmap: Path | None = None
    include_tags: bool = False
    fail_on_licence: bool = False
    auto_exclude: bool = True
    strip_metadata: bool = True
    set_identity: bool = True
    force_export: bool = False
    check_only: bool = False
    report_dir: Path | None = None


@dataclass(slots=True)
class HistoryResult(SquashResult):
    branch: str = ""
    commits: int = 0
    dropped_tags: list[str] = field(default_factory=list)
    dropped_paths: list[str] = field(default_factory=list)
    replaced_values: int = 0
    licence_history: list[Finding] = field(default_factory=list)
    survivors: list[str] = field(default_factory=list)
    filter_stats: dict[str, int] = field(default_factory=dict)


def is_licence_history(finding: Finding) -> bool:
    """Licence findings about history rather than the export ref: kept as they were."""
    return finding.category == "licence" and not finding.present_at_export_ref


def resolve_branch(runner: GitRunner, ref: str) -> str:
    """The short branch name `ref` names; anything else is a usage error (exit 2)."""
    if ref == "HEAD":
        full = runner.run(["rev-parse", "--symbolic-full-name", "HEAD"], check=False)
        name = full.decode().strip()
        if name.startswith("refs/heads/") and len(name) > len("refs/heads/"):
            return name.removeprefix("refs/heads/")
        raise UsageError("--keep-history needs a branch: HEAD is detached; pass --ref <branch>")
    name = ref.removeprefix("refs/heads/")
    try:
        runner.run(["show-ref", "--verify", "--quiet", f"refs/heads/{name}"])
    except GitError:
        raise UsageError(
            f"--keep-history needs a branch: {ref!r} is not a branch of the repository"
        ) from None
    return name


@dataclass(frozen=True, slots=True)
class Values:
    """Literal texts to replace, keyed by the source object that carries them."""

    blob: dict[str, list[str]]
    commit: dict[str, list[str]]
    tag: dict[str, list[str]]

    @property
    def count(self) -> int:
        return sum(len(v) for table in (self.blob, self.commit, self.tag) for v in table.values())


def collect_values(findings: list[Finding]) -> Values:
    """The literal values behind the unsuppressed findings, longest first per object."""
    tables: dict[str, dict[str, set[str]]] = {"blob": {}, "commit": {}, "tag": {}}
    for finding in findings:
        value = finding.raw_value
        loc = finding.location
        if not value or finding.category not in _REPLACED_CATEGORIES:
            continue
        if loc.kind not in _REPLACED_KINDS:
            continue
        if loc.kind == "blob" and loc.blob:
            tables["blob"].setdefault(loc.blob, set()).add(value)
        elif loc.kind == "commit_message" and loc.commit:
            tables["commit"].setdefault(loc.commit, set()).add(value)
        elif loc.kind == "tag_message" and loc.tag:
            tables["tag"].setdefault(loc.tag, set()).add(value)

    def ordered(table: dict[str, set[str]]) -> dict[str, list[str]]:
        return {oid: sorted(vals, key=lambda v: (-len(v), v)) for oid, vals in table.items()}

    return Values(
        blob=ordered(tables["blob"]),
        commit=ordered(tables["commit"]),
        tag=ordered(tables["tag"]),
    )


def compute_drop_paths(
    inventory: Inventory, findings: list[Finding], config: Config, *, auto_exclude: bool
) -> list[str]:
    """Every historical path the rewrite removes from every commit: `export.exclude`
    globs, sensitive and internal-notes files (with auto-exclude), paths whose
    unsuppressed finding is a deny term, and a tracked config that holds a deny list."""
    exclude_spec = pathspec.PathSpec.from_lines("gitwildmatch", config.export.exclude)
    files = FilesDetector(
        sensitive_files=tuple(config.files.sensitive_files),
        internal_notes=tuple(config.files.internal_notes),
    )
    flagged = {
        path
        for f in findings
        if f.location.kind == "path"
        and (f.rule_id.startswith("deny-") or f.rule_id == "tracked-config-deny")
        for path in f.location.paths
    }
    all_paths = {occ.path for occ in inventory.occurrences} | set(inventory.export_tree)
    dropped = {
        path
        for path in all_paths
        if path in flagged
        or exclude_spec.match_file(path)
        or (auto_exclude and files.detect_path(path))
    }
    return sorted(dropped)


def deny_paths_at_export_ref(findings: list[Finding]) -> list[Finding]:
    """A path at the export ref that contains a deny term: it must be renamed at HEAD."""
    return [
        f
        for f in findings
        if f.location.kind == "path" and f.rule_id.startswith("deny-") and f.present_at_export_ref
    ]


def child_command() -> list[str]:
    """`-P` keeps the clone (the working directory, whose files come from the audited
    repository) off `sys.path`, so a file named like a module cannot be imported."""
    return [sys.executable, "-P", "-m", "go_public.export._filter_child"]


def build_spec(
    request: HistoryRequest,
    values: Values,
    drop_paths: list[str],
    identity: Identity | None,
) -> dict[str, object]:
    return {
        "version": SPEC_VERSION,
        "identity": {"name": identity.name, "email": identity.email} if identity else None,
        "mailmap": str(request.mailmap.resolve()) if request.mailmap else None,
        "replacement": REMOVED,
        "blob_values": values.blob,
        "commit_values": values.commit,
        "tag_values": values.tag,
        "drop_paths": drop_paths,
        "flagged_trailers": list(request.config.trailers.flag),
        "strip_metadata": request.strip_metadata,
        "max_blob_bytes": request.config.files.high_mb * _ONE_MB,
    }


def run_history(request: HistoryRequest, log: Log) -> HistoryResult:
    """Run the history-preserving export (or only its pre-check with `check_only`)."""
    source_runner = GitRunner(request.source, role="source")
    if not request.check_only and request.author is None and request.mailmap is None:
        raise UsageError(
            "no export identity: pass --author 'Name <email>' (or set [export] author), "
            "or --mailmap <file> (go-public never reads your git config)"
        )
    if not request.check_only and request.out is None:
        raise UsageError("--out is required (unless --check)")
    if request.mailmap is not None and not request.mailmap.is_file():
        raise UsageError(f"--mailmap is not a file: {request.mailmap}")

    branch = resolve_branch(source_runner, request.ref)
    export_ref = f"refs/heads/{branch}"
    roots = repository_roots(source_runner)
    out = (
        validate_out_dir(request.out, source=request.source, roots=roots)
        if request.out is not None
        else None
    )
    if out is not None and not request.check_only:
        resolve_report_dir(
            repo_name=out.name, scanned_repo=out, override=request.report_dir, protected=roots
        )

    inventory = (
        build_head_only(source_runner, export_ref=export_ref)
        if request.check_only
        else build(source_runner, include_unreachable=False, export_ref=export_ref)
    )
    outcome = precheck.run(
        source_runner,
        inventory,
        request.config,
        request.scan_options,
        fail_on=request.fail_on,
        strip_metadata=request.strip_metadata,
        auto_exclude=request.auto_exclude,
    )
    blocking = list(outcome.blocking)
    seen = {f.fingerprint for f in blocking}
    blocking += [f for f in deny_paths_at_export_ref(outcome.findings) if f.fingerprint not in seen]
    result = HistoryResult(exit_code=0, blocking=blocking, branch=branch)
    if blocking:
        log(f"pre-check: {len(blocking)} finding(s) the export cannot resolve:")
        for finding in blocking:
            log(f"  {describe_finding(finding)}")
        if any(f.rule_id.startswith("deny-") and f.location.kind == "path" for f in blocking):
            log("a path that contains a deny term must be renamed at the export ref first")
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

    assert out is not None  # checked above
    result.out = out
    preexisting = out.exists()
    try:
        _export(request, source_runner, inventory, outcome.findings, out, result, roots, log)
    except BaseException:
        remove_partial(out, keep_dir=preexisting)
        raise
    return result


def _identity_env(identity: Identity) -> dict[str, str]:
    return {
        "GIT_AUTHOR_NAME": identity.name,
        "GIT_AUTHOR_EMAIL": identity.email,
        "GIT_COMMITTER_NAME": identity.name,
        "GIT_COMMITTER_EMAIL": identity.email,
    }


def _export(
    request: HistoryRequest,
    source_runner: GitRunner,
    inventory: Inventory,
    findings: list[Finding],
    out: Path,
    result: HistoryResult,
    roots: list[Path],
    log: Log,
) -> None:
    branch = result.branch
    out.parent.mkdir(parents=True, exist_ok=True)
    args = [
        "clone",
        "--no-local",
        "--single-branch",
        f"--branch={branch}",
        "--no-checkout",
    ]
    if not request.include_tags:
        args.append("--no-tags")
    with tempfile.TemporaryDirectory(prefix="go-public-template-") as template:
        args.append(f"--template={template}")
        args += [str(request.source), str(out)]
        GitRunner(out.parent, role="export").run(args)
    export_runner = GitRunner(out, role="export")
    identity = request.author if request.mailmap is None else None
    env = _identity_env(request.author or _FALLBACK_IDENTITY)

    result.dropped_tags = _detach_clone(export_runner, branch, findings, env)

    values = collect_values(findings)
    drop_paths = compute_drop_paths(
        inventory, findings, request.config, auto_exclude=request.auto_exclude
    )
    result.dropped_paths = drop_paths
    result.replaced_values = values.count
    spec = build_spec(request, values, drop_paths, identity)
    log(
        f"rewriting history of {branch}: {len(inventory.commits)} commit(s) in the source, "
        f"{values.count} value(s) to replace, {len(drop_paths)} path(s) to drop"
    )
    result.filter_stats = _run_child(spec, out, export_runner.child_env(env))

    shutil.rmtree(out / ".git" / "filter-repo", ignore_errors=True)
    export_runner.run(["rev-parse", "--verify", "refs/heads/main"])
    result.commits = int(export_runner.run(["rev-list", "--count", "HEAD"]).decode().strip())
    export_runner.run(["config", "commit.gpgsign", "false"])
    if request.set_identity and request.author is not None:
        export_runner.run(["config", "user.name", request.author.name])
        export_runner.run(["config", "user.email", request.author.email])

    forbidden = set(values.blob) | set(values.commit) | set(values.tag)
    result.survivors = _surviving_objects(export_runner, forbidden, env)

    stats = result.filter_stats
    log(
        f"exported {result.commits} commit(s) of {branch} as main to {out}: "
        f"{stats.get('blobs_replaced', 0)} file version(s) had values replaced, "
        f"{stats.get('blobs_stripped', 0)} had metadata stripped, "
        f"{stats.get('blobs_dropped', 0)} at or above {request.config.files.high_mb} MB dropped, "
        f"{len(result.dropped_paths)} path(s) and {len(result.dropped_tags)} tag(s) removed"
    )
    log("commit ids changed and signatures were dropped; licence history is kept as it was")

    exempt = None if request.fail_on_licence else is_licence_history
    assessment = rescan_export(
        out,
        request.author,
        config=request.config,
        config_source=request.config_source,
        scan_options=request.scan_options,
        git_version=request.git_version,
        fail_on=request.fail_on,
        report_dir=request.report_dir,
        source_roots=roots,
        result=result,
        log=log,
        exempt_from_exit=exempt,
    )
    result.licence_history = [f for f in assessment.findings if is_licence_history(f)]
    if result.licence_history:
        log(
            f"licence history: {len(result.licence_history)} finding(s) listed under group D "
            "need your decision"
            + (" (blocking, --fail-on-licence)" if request.fail_on_licence else " (not blocking)")
        )
    if result.survivors:
        result.clean = False
        result.exit_code = 1
        log(
            f"NOT CLEAN: {len(result.survivors)} object(s) that carried a finding are still in "
            "the export's object store"
        )
    if result.clean:
        log(
            f"To publish: create an empty repository on your host, then inside {out} run "
            "`git remote add origin <url>` followed by `git push -u origin main`."
        )


def _detach_clone(
    runner: GitRunner, branch: str, findings: list[Finding], env: dict[str, str]
) -> list[str]:
    """Remove the origin remote and its refs, drop tags with a deny term, and rename
    the branch to `main`. Returns the names of the tags dropped."""
    runner.run(["config", "--remove-section", "remote.origin"], check=False)
    runner.run(["config", "--remove-section", f"branch.{branch}"], check=False)
    refs = runner.run(["for-each-ref", "--format=%(refname)"]).decode().splitlines()
    flagged_tags = {
        f.location.ref
        for f in findings
        if f.location.kind == "ref_name"
        and f.location.ref
        and f.location.ref.startswith("refs/tags/")
    }
    doomed = [r for r in refs if r.startswith("refs/remotes/") or r in flagged_tags]
    if doomed:
        runner.run(
            ["update-ref", "--no-deref", "--stdin"],
            input="".join(f"delete {ref}\n" for ref in doomed).encode(),
            env=env,
        )
    if branch != "main":
        tip = runner.run(["rev-parse", "--verify", f"refs/heads/{branch}"]).decode().strip()
        runner.run(["update-ref", "refs/heads/main", tip], env=env)
        runner.run(["symbolic-ref", "HEAD", "refs/heads/main"], env=env)
        runner.run(["update-ref", "-d", f"refs/heads/{branch}"], env=env)
    return sorted(t.removeprefix("refs/tags/") for t in flagged_tags if t in refs)


def _run_child(spec: dict[str, object], out: Path, env: dict[str, str]) -> dict[str, int]:
    try:
        proc = subprocess.run(
            child_command(),
            cwd=out,
            input=json.dumps(spec).encode(),
            env=env,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise GitError(f"cannot start the git-filter-repo child process: {exc}") from exc
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-_STDERR_TAIL:]
        raise GitError(
            f"git-filter-repo failed (exit {proc.returncode}); the export was removed:\n"
            + "\n".join(tail)
        )
    for line in reversed(proc.stdout.decode("utf-8", "replace").splitlines()):
        if line.startswith(STATS_PREFIX):
            stats: dict[str, int] = json.loads(line[len(STATS_PREFIX) :])
            return stats
    raise ExportError("git-filter-repo child finished without reporting its result")


def _surviving_objects(runner: GitRunner, forbidden: set[str], env: dict[str, str]) -> list[str]:
    """Object ids among `forbidden` (source objects that carried a finding and were
    rewritten) still present in the export's object store. git-filter-repo expires the
    reflogs and prunes; when something survives anyway, expire and prune once more."""
    if not forbidden:
        return []

    def present() -> list[str]:
        listing = runner.run(["cat-file", "--batch-all-objects", "--batch-check"]).decode()
        found = {line.split(" ", 1)[0] for line in listing.splitlines()}
        return sorted(forbidden & found)

    left = present()
    if left:
        runner.run(["reflog", "expire", "--expire=now", "--all"], env=env)
        runner.run(["gc", "--prune=now", "--quiet"], env=env)
        left = present()
    return left
