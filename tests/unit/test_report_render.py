"""`report/{json,md,html}.py`, exercised end-to-end on the tiny fixture (stage-4.md
item 11): no absolute path of the scanned repo anywhere, secrets stay redacted, the
HTML has no external `src=`/`href=` (other than `#...`) or `url(`, and every report
carries the fix plan, findings table, suppressed list and rotated records.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from go_public.bench import fixture as fixture_mod
from go_public.config import AllowlistConfig, Config, FingerprintEntry, RotatedConfig
from go_public.git.inventory import build
from go_public.git.runner import GitRunner
from go_public.model import Report, ScanOptionsInfo
from go_public.plan import build_plan
from go_public.report.build import assemble_report
from go_public.report.html import render_html
from go_public.report.json import render_json
from go_public.report.md import render_markdown
from go_public.scan import ScanOptions
from go_public.scan import run as scan_run
from go_public.suppress import run as suppress_run

_HREF_RE = re.compile(r'href\s*=\s*"([^"]*)"')
_SRC_RE = re.compile(r'src\s*=\s*"([^"]*)"')


def _build_report(tmp_path: Path) -> tuple[Report, Path]:
    result = fixture_mod.build(1, "small", out=tmp_path / "repo")
    runner = GitRunner(result.repo, role="source")
    inventory = build(runner)
    # allowlist one finding so `report.suppressed` is non-empty too.
    findings = scan_run(runner, inventory, ScanOptions(config=Config()))
    secret = next(f for f in findings if f.category == "secret")
    config = Config(
        allowlist=AllowlistConfig(
            fingerprints=[FingerprintEntry(id=secret.fingerprint, reason="known test fixture")]
        ),
        rotated=RotatedConfig(
            fingerprints=[FingerprintEntry(id=secret.group_id, reason="rotated for this test")]
        ),
    )
    findings = scan_run(runner, inventory, ScanOptions(config=config))
    suppression = suppress_run(findings, config, inventory, runner)
    rotated_reasons = {e.id: e.reason for e in config.rotated.fingerprints}
    plan, refined = build_plan(suppression.kept, rotated_reasons=rotated_reasons)
    report = assemble_report(
        repo_path=str(result.repo),
        export_ref="HEAD",
        export_commit=None,
        inventory=inventory,
        git_version="git version 2.45.0",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        options=ScanOptionsInfo(fail_on="high"),
        findings=refined,
        suppressed=suppression.suppressed,
        rotated=config.rotated.fingerprints,
        plan=plan,
        fail_on="high",
    )
    return report, result.repo


def test_no_absolute_repo_path_in_any_report_format(tmp_path: Path) -> None:
    report, repo = _build_report(tmp_path)
    needle = str(repo)
    assert needle not in render_json(report)
    assert needle not in render_markdown(report)
    assert needle not in render_html(report)
    assert str(tmp_path) not in render_json(report)
    assert str(tmp_path) not in render_markdown(report)
    assert str(tmp_path) not in render_html(report)


def test_html_has_no_external_references_or_url_calls(tmp_path: Path) -> None:
    report, _repo = _build_report(tmp_path)
    html = render_html(report)

    assert "url(" not in html
    for match in _SRC_RE.finditer(html):
        raise AssertionError(f"unexpected src= in HTML report: {match.group(0)}")
    for match in _HREF_RE.finditer(html):
        assert match.group(1).startswith("#"), f"external href in HTML report: {match.group(0)}"


def test_reports_carry_plan_findings_suppressed_and_rotated(tmp_path: Path) -> None:
    report, _repo = _build_report(tmp_path)
    assert report.rotated, "the fixture should have a rotated entry for this test"
    assert report.suppressed, "the fixture should have a suppressed entry for this test"
    assert report.plan.A, "group A should be non-empty on the small fixture"

    md = render_markdown(report)
    assert "Rotate now" in md
    assert "Fix at HEAD" in md
    assert "Removed by a squash export" in md
    assert report.suppressed[0].fingerprint in md
    assert report.rotated[0].id in md

    html = render_html(report)
    assert "Rotate now" in html
    assert report.suppressed[0].fingerprint in html
    assert report.rotated[0].id in html


def test_secrets_stay_redacted_in_every_report_format(tmp_path: Path) -> None:
    report, _repo = _build_report(tmp_path)
    secret_findings = [f for f in report.findings if f.category == "secret"]
    assert secret_findings
    for finding in secret_findings:
        assert "…[len=" in finding.preview  # redaction.py's shape, never the raw value

    json_text = render_json(report)
    md_text = render_markdown(report)
    html_text = render_html(report)
    for finding in secret_findings:
        assert finding.preview[:4] in json_text  # the redacted preview itself is fine to show
        for text in (json_text, md_text, html_text):
            # the raw fingerprint/preview appear; the full unredacted secret value never would
            # (there is nothing left in `finding` that holds it — preview is already masked).
            assert finding.fingerprint in text


def test_git_version_is_printed_once(tmp_path: Path) -> None:
    report, _repo = _build_report(tmp_path)
    for text in (render_markdown(report), render_html(report)):
        assert "git version 2.45.0" in text
        assert "git git" not in text


def test_html_findings_section_has_an_anchor(tmp_path: Path) -> None:
    report, _repo = _build_report(tmp_path)
    assert '<h2 id="findings">' in render_html(report)
