"""Assembles a `model.Report` from a scan's raw ingredients (inventory, findings,
suppression and plan results). Not one of architecture.md's named files — a small,
separately testable seam between `cli.py`'s `scan` command and `report/json.py`/
`report/md.py`/`report/html.py` (recorded as a deviation in STATUS.md).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from go_public import __version__
from go_public.config import FingerprintEntry
from go_public.git.inventory import Inventory
from go_public.model import (
    Finding,
    InventoryInfo,
    PlanModel,
    RepoInfo,
    Report,
    RotatedInfo,
    ScanInfo,
    ScanOptionsInfo,
    SummaryInfo,
    SuppressedInfo,
    ToolInfo,
    WarningInfo,
    repo_display_name,
    severity_rank,
)
from go_public.suppress import SuppressedFinding


def _iso(when: datetime) -> str:
    return when.isoformat(timespec="seconds")


def build_repo_info(
    *, repo_path: str, export_ref: str, export_commit: str | None, inventory: Inventory
) -> RepoInfo:
    return RepoInfo(
        name=repo_display_name(repo_path),
        bare=inventory.repo_state.bare,
        object_format=inventory.repo_state.object_format,
        export_ref=export_ref,
        export_commit=export_commit,
    )


def build_inventory_info(inventory: Inventory) -> InventoryInfo:
    return InventoryInfo(
        refs=len(inventory.refs),
        commits=len(inventory.commits),
        tags=len(inventory.tags),
        unique_blobs=len(inventory.blob_sizes),
        total_bytes=inventory.total_bytes,
        unreachable_blobs=len(inventory.unreachable_blobs),
        ref_list=sorted(ref.name for ref in inventory.refs),
        missing_objects=len(inventory.missing_objects),
        lfs_pointers=len(inventory.lfs_pointers),
    )


def build_summary(findings: list[Finding], plan: PlanModel, *, fail_on: str) -> SummaryInfo:
    by_category = Counter(f.category for f in findings)
    by_severity = Counter(f.severity for f in findings)
    blocking = sum(1 for f in findings if severity_rank(f.severity) >= severity_rank(fail_on))
    return SummaryInfo(
        by_group={
            "A": len(plan.A),
            "B": len(plan.B),
            "C": len(plan.C),
            "D": len(plan.D),
        },
        by_category=dict(sorted(by_category.items())),
        by_severity=dict(sorted(by_severity.items())),
        blocking=blocking,
    )


def assemble_report(
    *,
    repo_path: str,
    export_ref: str,
    export_commit: str | None,
    inventory: Inventory,
    git_version: str,
    started_at: datetime,
    finished_at: datetime,
    options: ScanOptionsInfo,
    findings: list[Finding],
    suppressed: list[SuppressedFinding],
    rotated: list[FingerprintEntry],
    plan: PlanModel,
    fail_on: str,
) -> Report:
    """Build the full `Report`. `findings` is the refined (post-suppression,
    post-`plan.build_plan` fix-action) list; `exit_code` follows the same rule as
    `scan`'s own process exit code (0 clean, 1 findings at/above `--fail-on`)."""
    summary = build_summary(findings, plan, fail_on=fail_on)
    scan_info = ScanInfo(
        started_at=_iso(started_at),
        finished_at=_iso(finished_at),
        duration_s=max(0.0, (finished_at - started_at).total_seconds()),
        git_version=git_version,
        options=options,
    )
    return Report(
        tool=ToolInfo(version=__version__),
        repo=build_repo_info(
            repo_path=repo_path,
            export_ref=export_ref,
            export_commit=export_commit,
            inventory=inventory,
        ),
        scan=scan_info,
        inventory=build_inventory_info(inventory),
        warnings=[WarningInfo(code=w.code, message=w.message) for w in inventory.warnings],
        findings=findings,
        suppressed=[_suppressed_info(s) for s in suppressed],
        rotated=[RotatedInfo(id=r.id, reason=r.reason) for r in rotated],
        plan=plan,
        summary=summary,
        exit_code=1 if summary.blocking else 0,
    )


def _suppressed_info(s: SuppressedFinding) -> SuppressedInfo:
    return SuppressedInfo(
        fingerprint=s.fingerprint,
        group_id=s.group_id,
        category=s.category,
        rule_id=s.rule_id,
        source=s.source,
        reason=s.reason,
        pattern=s.pattern,
    )
