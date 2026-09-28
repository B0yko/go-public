"""The `go-public` command line. See architecture.md "CLI surface" for the full plan;
later stages add the remaining commands and options.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from pathlib import Path

import typer

from go_public import __version__
from go_public.bench import fixture as fixture_mod
from go_public.detect.gitleaks_config import load_gitleaks_config, rules_check
from go_public.errors import GoPublicError
from go_public.git.inventory import build, build_head_only
from go_public.git.runner import GitRunner, check_git_version

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
) -> None:
    """Scan a repository and print its inventory. Detectors and reports land in a later
    stage; for now this command builds the inventory and prints its summary line plus
    any warnings.
    """
    check_git_version()
    runner = GitRunner(repo.resolve(), role="source")
    if head_only:
        inventory = build_head_only(runner, export_ref=ref)
    else:
        inventory = build(runner, include_unreachable=include_unreachable, export_ref=ref)
    typer.echo(inventory.summary_line())
    for warning in inventory.warnings:
        typer.echo(f"warning: {warning.message}")


@app.command()
@_handle_errors
def fixture(
    seed: int = typer.Option(..., "--seed", help="Same seed, same repo."),
    size: str = typer.Option(..., "--size", help="tiny (runs in CI), small or medium."),
    no_plants: bool = typer.Option(
        False, "--no-plants", help="Filler and topology only, under the public identity."
    ),
    blind_spots: bool = typer.Option(
        False, "--blind-spots", help="Also build the blind-spot plants (not implemented yet)."
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
