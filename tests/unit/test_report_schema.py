"""`schemas/go-public-report-v1.json`: committed == generated,
and it validates a real (tiny-fixture) report plus an empty one."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema

from go_public.bench import fixture as fixture_mod
from go_public.config import Config
from go_public.git.inventory import build
from go_public.git.runner import GitRunner
from go_public.model import ScanOptionsInfo, report_json_schema
from go_public.plan import build_plan
from go_public.report.build import assemble_report
from go_public.scan import ScanOptions
from go_public.scan import run as scan_run
from go_public.suppress import run as suppress_run

from ..conftest import minimal_report

_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "go-public-report-v1.json"


def test_committed_schema_matches_generated_schema() -> None:
    committed = json.loads(_SCHEMA_PATH.read_text())
    assert committed == report_json_schema()


def test_schema_validates_a_real_fixture_scan(tmp_path: Path) -> None:
    result = fixture_mod.build(0, "tiny", out=tmp_path / "repo")
    runner = GitRunner(result.repo, role="source")
    inventory = build(runner)
    config = Config()
    findings = scan_run(runner, inventory, ScanOptions(config=config))
    suppressed = suppress_run(findings, config, inventory, runner)
    plan, refined = build_plan(suppressed.kept)
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
        suppressed=suppressed.suppressed,
        rotated=[],
        plan=plan,
        fail_on="high",
    )
    schema = json.loads(_SCHEMA_PATH.read_text())
    jsonschema.validate(json.loads(report.model_dump_json()), schema)
    assert str(tmp_path) not in report.model_dump_json()


def test_schema_validates_an_empty_report() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text())
    jsonschema.validate(json.loads(minimal_report().model_dump_json()), schema)
