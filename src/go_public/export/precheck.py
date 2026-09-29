"""The export pre-check: decide whether findings at the export ref block a squash
export.

A finding never blocks when it is resolved by the export process itself:

- anything not `present_at_export_ref` — a squash export only ever carries the
  export ref's current tree forward, so a history-only/message/identity/trailer/
  other-ref finding is dropped regardless (`plan.py`'s own group C is exactly this
  set, reused here as the same test);
- a gitlink, or a tracked `.go-public.toml` with a non-empty `[deny]` table — both are
  always dropped from the export tree (`export/squash.py` step 3), independent of any
  config;
- a path every one of whose occurrences matches `[export] exclude`, or (when
  auto-exclude is on) a `sensitive-file`/`internal-notes` finding — both are dropped
  from the export tree the same way (`export/squash.py` step 3 again);
- a `binary-metadata` finding whose rule id `plan.is_strip_resolvable` (metadata
  stripping is on by default; `--no-strip` turns it off) — `export/squash.py` strips
  these in memory before the blob ever reaches the export object store.

Everything else at or above `--fail-on` blocks the export unless `--force-export`.
`export --check` runs only this (via `run()`) and creates nothing under `--out`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import pathspec

from go_public import scan as scan_mod
from go_public import suppress as suppress_mod
from go_public.config import Config
from go_public.export.strip import residual_fields
from go_public.git.inventory import Inventory
from go_public.git.runner import GitRunner
from go_public.model import Finding, severity_rank
from go_public.plan import is_strip_resolvable
from go_public.suppress import SuppressedFinding

#: Always dropped from the export tree regardless of config (`export/squash.py` step
#: 3): a gitlink is never exported, and a tracked config with deny entries is dropped
#: so the deny-list itself never ships even unused.
_ALWAYS_DROPPED_RULE_IDS = frozenset({"gitlink", "tracked-config-deny"})

_AUTO_EXCLUDED_CATEGORIES = frozenset({"sensitive-file", "internal-notes"})


@dataclass(frozen=True, slots=True)
class PrecheckOutcome:
    """`findings`/`suppressed` are the full (post-suppression) scan result at the
    export ref's repository, reused by `export/squash.py` so it never re-scans the
    source repository twice; `blocking` is the subset that actually blocks the
    export."""

    inventory: Inventory
    findings: list[Finding]
    suppressed: list[SuppressedFinding]
    blocking: list[Finding]

    @property
    def clean(self) -> bool:
        return not self.blocking


def is_resolved_by_export(
    finding: Finding,
    *,
    export_exclude_spec: pathspec.PathSpec[pathspec.pattern.Pattern],
    auto_exclude: bool,
    strip_metadata: bool,
    strip_removes: Callable[[Finding], bool] | None = None,
) -> bool:
    """Whether the export process (`export/squash.py`) removes or fixes `finding` by
    itself, so it never needs to block `--fail-on`. `strip_removes` confirms from the
    blob's content that stripping really removes a binary-metadata field (the rule id
    alone cannot tell: TIFF carries EXIF that `strip` leaves alone)."""
    if not finding.present_at_export_ref:
        return True
    if finding.rule_id in _ALWAYS_DROPPED_RULE_IDS:
        return True
    paths = finding.location.paths
    if paths and all(export_exclude_spec.match_file(p) for p in paths):
        return True
    if auto_exclude and finding.category in _AUTO_EXCLUDED_CATEGORIES:
        return True
    if not (
        strip_metadata
        and finding.category == "binary-metadata"
        and is_strip_resolvable(finding.rule_id)
    ):
        return False
    return strip_removes is None or strip_removes(finding)


def blocking_findings(
    findings: list[Finding],
    *,
    config: Config,
    fail_on: str,
    strip_metadata: bool,
    auto_exclude: bool | None = None,
    strip_removes: Callable[[Finding], bool] | None = None,
) -> list[Finding]:
    """Every finding at or above `fail_on` that the export cannot resolve by itself.
    `auto_exclude` (the `--no-auto-exclude` switch) defaults to `[files] auto_exclude`."""
    if auto_exclude is None:
        auto_exclude = config.files.auto_exclude
    export_exclude_spec = pathspec.PathSpec.from_lines("gitwildmatch", config.export.exclude)
    return [
        finding
        for finding in findings
        if severity_rank(finding.severity) >= severity_rank(fail_on)
        and not is_resolved_by_export(
            finding,
            export_exclude_spec=export_exclude_spec,
            auto_exclude=auto_exclude,
            strip_metadata=strip_metadata,
            strip_removes=strip_removes,
        )
    ]


def _strip_check(runner: GitRunner) -> Callable[[Finding], bool]:
    """A `strip_removes` callback that reads each blob once and asks the stripper what
    it would leave behind."""
    residual: dict[str, set[tuple[str, str]]] = {}

    def strip_removes(finding: Finding) -> bool:
        blob = finding.location.blob
        if blob is None or finding.location.field is None:
            return False
        if blob not in residual:
            residual[blob] = residual_fields(runner.run(["cat-file", "blob", blob]))
        return (finding.rule_id, finding.location.field) not in residual[blob]

    return strip_removes


def run(
    runner: GitRunner,
    inventory: Inventory,
    config: Config,
    scan_options: scan_mod.ScanOptions,
    *,
    fail_on: str,
    strip_metadata: bool,
    auto_exclude: bool | None = None,
) -> PrecheckOutcome:
    """Scan `inventory` (the source repository at the export ref), suppress exactly as
    `go-public scan` would, and compute what still blocks the export."""
    findings = scan_mod.run(runner, inventory, scan_options)
    suppression = suppress_mod.run(findings, config, inventory, runner)
    blocking = blocking_findings(
        suppression.kept,
        config=config,
        fail_on=fail_on,
        strip_metadata=strip_metadata,
        auto_exclude=auto_exclude,
        strip_removes=_strip_check(runner),
    )
    return PrecheckOutcome(
        inventory=inventory,
        findings=suppression.kept,
        suppressed=suppression.suppressed,
        blocking=blocking,
    )
