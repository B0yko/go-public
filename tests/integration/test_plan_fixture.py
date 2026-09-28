"""`plan.py`'s grouping, exercised on the real tiny fixture (stage-4.md's own test
list): every secret in A; present-at-head items in B; history-only items in C;
licence/large-file in D; a rotated secret still shows done in A but still blocks
group B and the exit code.
"""

from __future__ import annotations

from pathlib import Path

from go_public.bench import fixture as fixture_mod
from go_public.config import Config
from go_public.git.inventory import build
from go_public.git.runner import GitRunner
from go_public.model import severity_rank
from go_public.plan import build_plan
from go_public.scan import ScanOptions
from go_public.scan import run as scan_run
from go_public.suppress import run as suppress_run


def _tiny_findings(tmp_path: Path) -> tuple[list, object, GitRunner]:  # type: ignore[type-arg]
    result = fixture_mod.build(0, "tiny", out=tmp_path / "repo")
    runner = GitRunner(result.repo, role="source")
    inventory = build(runner)
    config = Config()
    findings = scan_run(runner, inventory, ScanOptions(config=config))
    suppression = suppress_run(findings, config, inventory, runner)
    return suppression.kept, inventory, runner


def test_every_secret_group_appears_in_group_a(tmp_path: Path) -> None:
    findings, _inventory, _runner = _tiny_findings(tmp_path)
    plan, _ = build_plan(findings)

    secret_group_ids = {f.group_id for f in findings if f.category == "secret"}
    a_group_ids = {entry.secret_id for entry in plan.A}
    assert secret_group_ids
    assert secret_group_ids == a_group_ids


def test_head_items_are_in_b_history_only_in_c_licence_large_in_d(tmp_path: Path) -> None:
    findings, _inventory, _runner = _tiny_findings(tmp_path)
    plan, _ = build_plan(findings)

    b_fingerprints = {fp for g in plan.B for fp in g.findings}
    c_fingerprints = {fp for g in plan.C for fp in g.findings}
    d_fingerprints = {fp for d in plan.D for fp in d.findings}

    for finding in findings:
        if finding.category == "licence":
            assert finding.fingerprint in d_fingerprints
        elif finding.category == "large-file":
            expected = d_fingerprints if finding.present_at_export_ref else c_fingerprints
            assert finding.fingerprint in expected
        elif finding.present_at_export_ref:
            assert finding.fingerprint in b_fingerprints
        else:
            assert finding.fingerprint in c_fingerprints

    # every group actually has real content (the tiny fixture always plants both).
    assert plan.D
    assert plan.B
    assert plan.C


def test_rotated_secret_shows_done_but_still_blocks_group_b_and_exit_code(
    tmp_path: Path,
) -> None:
    findings, _inventory, _runner = _tiny_findings(tmp_path)
    secret_findings = [f for f in findings if f.category == "secret"]
    assert secret_findings
    target_group = secret_findings[0].group_id

    plan_open, refined_open = build_plan(findings)
    plan_rotated, refined_rotated = build_plan(
        findings, rotated_reasons={target_group: "rotated in vault"}
    )

    open_entry = next(e for e in plan_open.A if e.secret_id == target_group)
    rotated_entry = next(e for e in plan_rotated.A if e.secret_id == target_group)
    assert open_entry.status == "open"
    assert rotated_entry.status == "rotated"
    assert rotated_entry.rotated_reason == "rotated in vault"

    # rotation never suppresses: the same fingerprints still land in B/C either way.
    b_before = {fp for g in plan_open.B for fp in g.findings}
    b_after = {fp for g in plan_rotated.B for fp in g.findings}
    c_before = {fp for g in plan_open.C for fp in g.findings}
    c_after = {fp for g in plan_rotated.C for fp in g.findings}
    assert b_before == b_after
    assert c_before == c_after

    # and the blocking/exit-code calculation (severity vs. fail_on) is unaffected by
    # rotation status: rotating a secret never un-blocks the scan by itself.
    def _blocking(refined: list) -> int:  # type: ignore[type-arg]
        return sum(1 for f in refined if severity_rank(f.severity) >= severity_rank("high"))

    assert _blocking(refined_open) == _blocking(refined_rotated)
    assert _blocking(refined_rotated) > 0
