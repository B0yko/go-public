"""The `go-public` command line. See architecture.md "CLI surface" for the full plan;
later stages add the remaining commands and options.
"""

from __future__ import annotations

import functools
import json
import os
from collections import Counter
from collections.abc import Callable
from pathlib import Path

import typer

from go_public import __version__, config_write, fileview, pipeline
from go_public import config as config_mod
from go_public import scan as scan_mod
from go_public.bench import fixture as fixture_mod
from go_public.detect import commit_meta
from go_public.detect.gitleaks_config import load_gitleaks_config, rules_check
from go_public.errors import GoPublicError, UsageError
from go_public.export import squash as squash_mod
from go_public.export import strip as strip_mod
from go_public.git.inventory import Inventory, build, repository_roots
from go_public.git.runner import GitRunner, check_git_version
from go_public.model import SEVERITIES, Finding, repo_display_name
from go_public.report.build import write_reports

app = typer.Typer(add_completion=False, no_args_is_help=True, pretty_exceptions_enable=False)
rules_app = typer.Typer(add_completion=False, no_args_is_help=True)
app.add_typer(rules_app, name="rules", help="Inspect the gitleaks-format rule set.")


def _handle_errors[F: Callable[..., None]](func: F) -> F:
    """Turn a `GoPublicError` into the matching process exit code.

    `typer.Exit` is a click exception, so it is handled the same way whether the
    command runs through `main()`, `python -m go_public`, or `CliRunner` in tests.
    """

    @functools.wraps(func)
    def wrapper(*args: object, **kwargs: object) -> None:
        try:
            func(*args, **kwargs)
        except GoPublicError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=exc.exit_code) from None

    return wrapper  # type: ignore[return-value]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"go-public {__version__}")
        raise typer.Exit(0)


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Audit a private git repository and produce a clean export before you open-source it."""


@app.command()
@_handle_errors
def scan(
    repo: Path = typer.Argument(
        ..., exists=True, file_okay=False, help="Path to the git repository."
    ),
    ref: str = typer.Option("HEAD", "--ref", help="Export ref to scan against."),
    config_path: Path | None = typer.Option(
        None,
        "--config",
        exists=True,
        dir_okay=False,
        help="TOML config (deny list, identity allowlist, ...). Defaults to the built-in defaults.",
    ),
    detect_names: bool = typer.Option(
        False,
        "--detect-names",
        help="Also search content for every non-allowlisted identity's name from history.",
    ),
    include_unreachable: bool = typer.Option(
        False,
        "--include-unreachable",
        help="Also scan every object in the object database (dangling, reflog-only).",
    ),
    head_only: bool = typer.Option(
        False,
        "--head-only",
        help="Scan only the tree at --ref; no history, messages or identities.",
    ),
    gitleaks_config: Path | None = typer.Option(
        None,
        "--gitleaks-config",
        exists=True,
        dir_okay=False,
        help="Defaults to the bundled gitleaks rule set.",
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Minimum severity that makes scan exit 1 (default: [scan] fail_on, else high).",
    ),
    jobs: int = typer.Option(
        0, "--jobs", help="Worker processes for blob scanning (0 = CPU count)."
    ),
    show_secrets: bool = typer.Option(
        False, "--show-secrets", help="Print full secret values in previews (off by default)."
    ),
    summary_json: bool = typer.Option(
        False, "--summary-json", help="Print only a JSON summary on stdout."
    ),
    report_dir: Path | None = typer.Option(
        None, "--report-dir", help="Override the default report location."
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress the human-readable stdout output."),
    debug_json: Path | None = typer.Option(
        None,
        "--debug-json",
        hidden=True,
        help="Write the raw finding list as JSON (for tests); must be outside the repo.",
    ),
) -> None:
    """Scan a repository: inventory, detectors, suppression, fix plan and reports.

    Prints the inventory line, warnings and a finding-count summary (unless
    `--quiet`/`--summary-json`), writes `report.json`/`report.md`/`report.html`
    under the report location (`--report-dir` overrides it), and exits according to
    `--fail-on`.
    """
    git_version = check_git_version()
    repo_resolved = repo.resolve()
    runner = GitRunner(repo_resolved, role="source")
    discovery = config_mod.discover_config(
        explicit=config_path, repo=repo_resolved, runner=runner, export_ref=ref
    )
    config = discovery.config
    if detect_names:
        config = config.model_copy(
            update={"pii": config.pii.model_copy(update={"detect_names": True})}
        )
    effective_fail_on = fail_on if fail_on is not None else config.scan.fail_on
    _check_fail_on(effective_fail_on)

    quiet_stdout = quiet or summary_json

    def announce_inventory(inventory: Inventory) -> None:
        if quiet_stdout:
            return
        typer.echo(inventory.summary_line())
        for warning in inventory.warnings:
            typer.echo(f"warning: {warning.message}")
        for message in discovery.warnings:
            typer.echo(f"warning: {message}")

    def write_debug_json(raw_findings: list[Finding]) -> None:
        if debug_json is not None:
            debug_json.write_text(json.dumps([f.model_dump() for f in raw_findings]))

    options = scan_mod.ScanOptions.from_config(
        config,
        gitleaks_config=str(gitleaks_config) if gitleaks_config else None,
        jobs=jobs,
        show_secrets=show_secrets,
    )
    assessment = pipeline.assess(
        runner,
        repo_path=repo_resolved,
        ref=ref,
        config=config,
        config_source=discovery.source,
        options=options,
        git_version=git_version,
        fail_on=effective_fail_on,
        include_unreachable=include_unreachable,
        head_only=head_only,
        on_inventory=announce_inventory,
        on_raw_findings=write_debug_json,
    )
    report_obj = assessment.report
    refined_findings = assessment.findings

    report_paths = write_reports(
        report_obj, repo_resolved, report_dir, protected=repository_roots(runner)
    )

    if summary_json:
        typer.echo(
            json.dumps(
                {
                    "groups": report_obj.summary.by_group,
                    "by_category": report_obj.summary.by_category,
                    "by_severity": report_obj.summary.by_severity,
                    "blocking": report_obj.summary.blocking,
                    "exit_code": report_obj.exit_code,
                    "reports": {k: str(v) for k, v in report_paths.items()},
                }
            )
        )
    elif not quiet:
        _print_finding_counts(refined_findings)
        typer.echo(f"reports written to {report_paths['json'].parent}")

    if report_obj.exit_code:
        raise typer.Exit(code=report_obj.exit_code)


def _check_fail_on(value: str) -> None:
    if value not in SEVERITIES:
        raise UsageError(f"--fail-on: unknown severity {value!r} (expected one of {SEVERITIES})")


def _print_finding_counts(findings: list[Finding]) -> None:
    total = len(findings)
    typer.echo(f"{total} finding(s)")
    if not total:
        return
    by_category: Counter[str] = Counter(f.category for f in findings)
    by_severity: Counter[str] = Counter(f.severity for f in findings)
    category_line = ", ".join(f"{k}={v}" for k, v in sorted(by_category.items()))
    severity_line = ", ".join(
        f"{sev}={by_severity[sev]}" for sev in reversed(SEVERITIES) if by_severity.get(sev)
    )
    typer.echo(f"  by category: {category_line}")
    typer.echo(f"  by severity: {severity_line}")


@app.command()
@_handle_errors
def export(
    repo: Path = typer.Argument(
        ..., exists=True, file_okay=False, help="Path to the git repository (bare is fine)."
    ),
    out: Path | None = typer.Option(
        None, "--out", help="New export directory: must not exist or be empty, outside the repo."
    ),
    squash: bool = typer.Option(
        True, "--squash/--keep-history", help="Squash export (default); --keep-history: later."
    ),
    ref: str = typer.Option("HEAD", "--ref", help="Export ref."),
    check: bool = typer.Option(
        False, "--check", help="Run only the pre-check: create nothing, exit 0 or 1."
    ),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Minimum severity that blocks the export (default: [scan] fail_on)."
    ),
    force_export: bool = typer.Option(
        False, "--force-export", help="Export even if the pre-check finds blocking items."
    ),
    author: str | None = typer.Option(
        None, "--author", help='Export identity "Name <email>" (default: [export] author).'
    ),
    message: str | None = typer.Option(
        None, "--message", help="Commit message (default: [export] message)."
    ),
    date: str | None = typer.Option(
        None, "--date", help='"now" or an ISO 8601 timestamp (default: [export] date).'
    ),
    auto_exclude: bool = typer.Option(
        True,
        "--auto-exclude/--no-auto-exclude",
        help="Drop sensitive and internal-notes files from the export.",
    ),
    strip_metadata: bool = typer.Option(
        True, "--strip/--no-strip", help="Strip binary metadata in memory before writing blobs."
    ),
    set_identity: bool = typer.Option(
        True,
        "--set-identity/--no-set-identity",
        help="Set the export repository's local user.name/user.email to the export identity.",
    ),
    config_path: Path | None = typer.Option(
        None, "--config", exists=True, dir_okay=False, help="TOML config."
    ),
    report_dir: Path | None = typer.Option(
        None, "--report-dir", help="Override the re-scan report location."
    ),
) -> None:
    """Export a clean, single-commit copy of the repository at --ref.

    Runs the pre-check, builds the export in a fresh repository, checks it out and
    re-scans it. Exits 1 when the pre-check refuses or the export is NOT CLEAN.
    """
    if not squash:
        raise UsageError("--keep-history is not available yet; only the squash export exists")
    if out is None and not check:
        raise UsageError("--out is required (unless --check)")
    git_version = check_git_version()
    repo_resolved = repo.resolve()
    runner = GitRunner(repo_resolved, role="source")
    discovery = config_mod.discover_config(
        explicit=config_path, repo=repo_resolved, runner=runner, export_ref=ref
    )
    config = discovery.config
    for warning in discovery.warnings:
        typer.echo(f"warning: {warning}")
    effective_fail_on = fail_on if fail_on is not None else config.scan.fail_on
    _check_fail_on(effective_fail_on)
    author_text = author if author is not None else config.export.author
    identity = squash_mod.parse_identity(author_text) if author_text.strip() else None
    request = squash_mod.SquashRequest(
        source=repo_resolved,
        out=out,
        ref=ref,
        config=config,
        config_source=discovery.source,
        scan_options=scan_mod.ScanOptions.from_config(config),
        git_version=git_version,
        fail_on=effective_fail_on,
        author=identity,
        message=message if message is not None else config.export.message,
        commit_date=squash_mod.resolve_commit_date(
            date if date is not None else config.export.date
        ),
        auto_exclude=auto_exclude and config.files.auto_exclude,
        strip_metadata=strip_metadata and config.export.strip_metadata,
        set_identity=set_identity,
        force_export=force_export,
        check_only=check,
        report_dir=report_dir,
    )
    result = squash_mod.run_squash(request, typer.echo)
    if result.exit_code:
        raise typer.Exit(code=result.exit_code)


@app.command()
@_handle_errors
def strip(
    files: list[Path] = typer.Argument(..., help="Files to strip in place."),
    check: bool = typer.Option(
        False, "--check", help="Only list what would be removed; exit 1 if anything is present."
    ),
) -> None:
    """Remove metadata losslessly (JPEG, PNG, WebP, PDF, OOXML) in place."""
    found = False
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise UsageError(f"not a regular file: {path}")
        content = path.read_bytes()
        removable = strip_mod.describe(content)
        for note in strip_mod.reported_only(content):
            typer.echo(f"{path}: reported, not removed: {note}")
        if not removable:
            continue
        found = True
        if check:
            typer.echo(f"{path}: would remove {', '.join(removable)}")
            continue
        path.write_bytes(strip_mod.strip_bytes(content))
        typer.echo(f"{path}: removed {', '.join(removable)}")
    if check and found:
        raise typer.Exit(code=1)


@app.command()
@_handle_errors
def show(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, help="Path to the repository."),
    path: str = typer.Argument(..., help="Repository-relative path of the file."),
    ref: str = typer.Option("HEAD", "--ref", help="Ref to read the file at."),
    config_path: Path | None = typer.Option(
        None, "--config", exists=True, dir_okay=False, help="TOML config."
    ),
) -> None:
    """Print a file at a ref with every secret span masked."""
    check_git_version()
    repo_resolved = repo.resolve()
    runner = GitRunner(repo_resolved, role="source")
    config = config_mod.discover_config(
        explicit=config_path, repo=repo_resolved, runner=runner, export_ref=ref
    ).config
    text = fileview.show_file(runner, path, ref, scan_mod.ScanOptions.from_config(config))
    typer.echo(text, nl=False)


@app.command()
@_handle_errors
def redact(
    path: Path = typer.Argument(..., help="Working-tree file to edit in place."),
    finding: str = typer.Option(
        ..., "--finding", help="Finding fingerprint (for this file's content) or secret group id."
    ),
    placeholder: str = typer.Option(..., "--with", help="Replacement text."),
    config_path: Path | None = typer.Option(
        None, "--config", exists=True, dir_okay=False, help="TOML config."
    ),
) -> None:
    """Replace one secret in a working-tree file; never touches the index or history."""
    env_config = os.environ.get("GO_PUBLIC_CONFIG")
    config = config_mod.load_config(config_path or env_config or None)
    result = fileview.redact_file(
        path, finding, placeholder, scan_mod.ScanOptions.from_config(config)
    )
    typer.echo(f"redacted 1 secret ({result.rule_id}) at {path}:{result.line}:{result.column}")


@app.command()
@_handle_errors
def allow(
    fingerprint: str = typer.Argument(
        ..., help="A finding's fingerprint, or (with --rotated) its secret group id."
    ),
    reason: str = typer.Option(..., "--reason", help="Why this is allowlisted (required)."),
    rotated: bool = typer.Option(
        False, "--rotated", help="Record this secret as rotated instead of allowlisting it."
    ),
    repo: Path | None = typer.Option(
        None, "--repo", help="Repository this finding belongs to (default: the current directory)."
    ),
    config_path: Path | None = typer.Option(
        None, "--config", dir_okay=False, help="Config file to write (default: the XDG file)."
    ),
) -> None:
    """Allowlist a finding, or (with `--rotated`) record its secret as rotated.

    `--rotated` looks up the repository's latest scan report (`go-public scan` must
    have run first) to resolve `fingerprint` to its secret's group id, and refuses a
    non-secret finding.
    """
    if not reason.strip():
        raise UsageError("--reason must not be empty")
    repo_resolved = (repo or Path.cwd()).resolve()
    target_config = config_path or config_mod.xdg_config_path(repo_resolved)
    if rotated:
        report = config_write.load_latest_report(repo_display_name(str(repo_resolved)))
        group_id = config_write.resolve_secret_group_id(report, fingerprint)
        config_write.append_rotated(target_config, group_id, reason)
        typer.echo(f"recorded {group_id} as rotated in {target_config}")
    else:
        config_write.append_allow_fingerprint(target_config, fingerprint, reason)
        typer.echo(f"allowlisted {fingerprint} in {target_config}")


@app.command()
@_handle_errors
def init(
    repo: Path = typer.Argument(
        ..., exists=True, file_okay=False, help="Path to the git repository."
    ),
    config_path: Path | None = typer.Option(
        None, "--config", dir_okay=False, help="Write here instead of the XDG file."
    ),
) -> None:
    """Write a commented config template for `repo` (never inside the repository)."""
    check_git_version()
    repo_resolved = repo.resolve()
    target_config = config_path or config_mod.xdg_config_path(repo_resolved)
    if target_config.exists():
        raise UsageError(f"refusing to overwrite existing config: {target_config}")

    runner = GitRunner(repo_resolved, role="source")
    inventory = build(runner)
    occurrences = commit_meta.collect_identities(inventory.commits, inventory.tags)
    identities = sorted({occ.identity for occ in occurrences})

    text = config_write.build_init_template(repo_resolved, identities)
    target_config.parent.mkdir(parents=True, exist_ok=True)
    target_config.write_text(text, encoding="utf-8")
    typer.echo(f"wrote {target_config}")


@app.command()
@_handle_errors
def fixture(
    seed: int = typer.Option(..., "--seed", help="Same seed, same repo."),
    size: str = typer.Option(
        ..., "--size", help="tiny (runs in CI), small, or medium (runtime only)."
    ),
    no_plants: bool = typer.Option(
        False, "--no-plants", help="Filler and topology only, under the public identity."
    ),
    blind_spots: bool = typer.Option(
        False, "--blind-spots", help="Also build the blind-spot plants (truth.blind.jsonl)."
    ),
    out: Path = typer.Option(..., "--out", help="Directory for repo/, truth.jsonl, config."),
) -> None:
    """Build a synthetic fixture repository for benchmarking the detectors."""
    check_git_version()
    result = fixture_mod.build(seed, size, plants=not no_plants, blind_spots=blind_spots, out=out)
    typer.echo(f"fixture: {result.repo}")


@rules_app.command("check")
@_handle_errors
def rules_check_cmd(
    gitleaks_config: Path | None = typer.Option(
        None,
        "--gitleaks-config",
        exists=True,
        dir_okay=False,
        help="Defaults to the bundled rules.",
    ),
) -> None:
    """Compile the rule set and report how many rules and allowlist regexes loaded."""
    config = load_gitleaks_config(gitleaks_config)
    for warning in config.warnings:
        typer.echo(f"warning: {warning}")
    result = rules_check(config)
    typer.echo(result.summary_line())
    for failure in result.failures:
        typer.echo(f"failed to compile: {failure.context}: {failure.pattern!r}: {failure.message}")
    if result.failures:
        raise typer.Exit(code=1)


def main() -> None:
    """Entry point for the `go-public` console script; maps errors to exit codes."""
    try:
        app()
    except GoPublicError as exc:
        typer.echo(str(exc), err=True)
        raise SystemExit(exc.exit_code) from None


if __name__ == "__main__":
    main()
