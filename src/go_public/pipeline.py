"""The scan-to-report pipeline shared by `go-public scan` and the squash export's
post-export re-scan (product spec item 14 step 7): inventory, detectors, suppression,
fix plan and `Report` assembly. Writing the report files is `report.build.write_reports`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from go_public import plan as plan_mod
from go_public import scan as scan_mod
from go_public import suppress as suppress_mod
from go_public.config import Config
from go_public.errors import GitError
from go_public.git.inventory import Inventory, build, build_head_only
from go_public.git.runner import GitRunner
from go_public.model import Finding, Report, ScanOptionsInfo
from go_public.report.build import assemble_report


@dataclass(frozen=True, slots=True)
class Assessment:
    """The result of one scan: `findings` are the unsuppressed findings with their
    fix actions refined by the plan (the same list `report.findings` holds)."""

    inventory: Inventory
    findings: list[Finding]
    report: Report


def resolve_export_commit(runner: GitRunner, ref: str) -> str | None:
    try:
        return runner.run(["rev-parse", ref]).decode().strip()
    except GitError:
        return None


def assess(
    runner: GitRunner,
    *,
    repo_path: Path,
    ref: str,
    config: Config,
    config_source: str,
    options: scan_mod.ScanOptions,
    git_version: str,
    fail_on: str,
    include_unreachable: bool = False,
    head_only: bool = False,
    on_inventory: Callable[[Inventory], None] | None = None,
    on_raw_findings: Callable[[list[Finding]], None] | None = None,
    exempt_from_exit: Callable[[Finding], bool] | None = None,
) -> Assessment:
    """Scan `repo_path` (read through `runner`) against `ref` and assemble its report.

    `on_inventory` runs right after the inventory is built (the CLI prints the
    inventory line and warnings from it before the slow scan starts); `on_raw_findings`
    receives the findings before suppression. `exempt_from_exit` names findings that
    stay in the report but do not count towards the exit decision.
    """
    started_at = datetime.now(UTC)
    if head_only:
        inventory = build_head_only(runner, export_ref=ref)
    else:
        inventory = build(runner, include_unreachable=include_unreachable, export_ref=ref)
    if on_inventory is not None:
        on_inventory(inventory)

    findings = scan_mod.run(runner, inventory, options)
    if on_raw_findings is not None:
        on_raw_findings(findings)

    suppression = suppress_mod.run(findings, config, inventory, runner)
    rotated_reasons = {entry.id: entry.reason for entry in config.rotated.fingerprints}
    plan, refined = plan_mod.build_plan(
        suppression.kept,
        rotated_reasons=rotated_reasons,
        export_paths=set(inventory.export_tree),
    )

    report = assemble_report(
        repo_path=str(repo_path),
        export_ref=ref,
        export_commit=resolve_export_commit(runner, ref),
        inventory=inventory,
        git_version=git_version,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        options=ScanOptionsInfo(
            include_unreachable=include_unreachable,
            head_only=head_only,
            fail_on=fail_on,
            jobs=options.jobs,
            detect_names=config.pii.detect_names,
            show_secrets=options.show_secrets,
            config_source=config_source,
        ),
        findings=refined,
        suppressed=suppression.suppressed,
        rotated=config.rotated.fingerprints,
        plan=plan,
        fail_on=fail_on,
        exempt_from_exit=exempt_from_exit,
    )
    return Assessment(inventory=inventory, findings=refined, report=report)
