"""`go-public bench` and `go-public demo` end to end on tiny fixtures (the CI smoke)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from go_public.bench import run as bench_run
from go_public.bench.plants import blind_spots
from go_public.cli import app
from go_public.config import load_config
from go_public.export import squash as squash_mod
from go_public.git.runner import check_git_version
from go_public.scan import ScanOptions

runner = CliRunner()


def _bench(tmp_path: Path, *args: str) -> tuple[int, str, Path]:
    out = tmp_path / "results"
    result = runner.invoke(
        app, ["bench", "--size", "tiny", "--out", str(out), "--jobs", "1", *args]
    )
    return result.exit_code, result.stdout + result.stderr, out


def test_smoke_gate_on_tiny_seed_0(tmp_path: Path) -> None:
    code, output, out = _bench(tmp_path, "--seeds", "0", "--gate", "--detector-commit", "abc1234")
    assert code == 0, output
    data = json.loads((out / "synthetic-tiny-0.json").read_text())
    assert data["gates_pass"] is True
    assert data["meta"]["detector_commit"] == "abc1234"
    assert data["meta"]["seeds"] == [0]
    assert set(data["classes"]) == set(bench_run.EVAL_CLASSES)
    row = data["classes"]["secret-vendor"]
    assert row["tp"] + row["fn"] == row["expected_findings"]
    assert row["fp"] == 0 and row["gate"] == 0.95
    assert (out / "synthetic-tiny-0.md").read_text().startswith("# Synthetic bench")


def test_smoke_gate_on_tiny_seeds_0_and_1(tmp_path: Path) -> None:
    code, output, out = _bench(tmp_path, "--seeds", "0,1", "--gate")
    assert code == 0, output
    assert (out / "synthetic-tiny-0_1.json").exists()


def test_results_files_hold_no_paths_or_host_names(tmp_path: Path) -> None:
    code, output, out = _bench(
        tmp_path, "--seeds", "0", "--compare-head-only", "--export-verify", "--blind-spots"
    )
    assert code == 0, output
    names = sorted(p.name for p in out.iterdir())
    assert names == [
        "blind-spots-tiny-0.json",
        "blind-spots-tiny-0.md",
        "export-verify-tiny-0.json",
        "export-verify-tiny-0.md",
        "head-only-compare-tiny-0.json",
        "head-only-compare-tiny-0.md",
    ]
    for path in out.iterdir():
        bench_run.assert_sanitised(path.read_text(), extra=(str(tmp_path),))


def test_head_only_compare_shows_history_locations_are_invisible_to_head_only(
    tmp_path: Path,
) -> None:
    code, output, out = _bench(tmp_path, "--seeds", "0", "--compare-head-only")
    assert code == 0, output
    data = json.loads((out / "head-only-compare-tiny-0.json").read_text())
    groups = data["by_location"]
    assert data["overall"]["full_recall"] == 1.0
    assert groups["history-only"]["head_only_found"] == 0
    assert groups["side branch"]["head_only_found"] == 0
    assert groups["head"]["head_only_recall"] == 1.0
    assert data["overall"]["head_only_recall"] < 0.6


def test_export_verify_squash_eliminates_everything(tmp_path: Path) -> None:
    code, output, out = _bench(tmp_path, "--seeds", "0", "--export-verify", "--gate")
    assert code == 0, output
    block = json.loads((out / "export-verify-tiny-0.json").read_text())["modes"]["squash"]
    seed = block["seeds"][0]
    assert seed["history_only_eliminated"] == seed["history_only_total"] > 0
    assert seed["head_auto_eliminated"] == seed["head_auto_total"] > 0
    assert seed["residual_true"] == 0 and seed["residual_false_positives"] == 0
    assert seed["immutable"] is True and seed["clean"] is True and not seed["refused"]


def test_the_scripted_fix_is_what_makes_the_export_possible(tmp_path: Path) -> None:
    """Without the fix commit the pre-check refuses: the verify run is not vacuous."""
    options = bench_run.BenchOptions(seed_spec="0", size="tiny", out=tmp_path / "r", jobs=1)
    with bench_run.Workspace(options) as workspace:
        unfixed = workspace.fixture(0)
        config = load_config(unfixed.result.config_path)
        request = squash_mod.SquashRequest(
            source=unfixed.result.repo,
            out=workspace.root / "export",
            ref="HEAD",
            config=config,
            config_source="fixture",
            scan_options=ScanOptions.from_config(config, jobs=1),
            git_version=check_git_version(),
            fail_on="low",
            author=squash_mod.parse_identity(config.export.author),
            message="x",
            commit_date=squash_mod.resolve_commit_date("now"),
            report_dir=workspace.root / "rep",
        )
        result = squash_mod.run_squash(request, lambda _line: None)
        assert result.exit_code == 1 and result.blocking


def test_scripted_fix_variant_moves_neutralised_plants_to_history(tmp_path: Path) -> None:
    from go_public.bench import fixture

    result = fixture.build(0, "tiny", scripted_fix=True, out=tmp_path / "f")
    assert result.fix is not None and result.fix.neutralised and result.fix.auto_resolved
    from go_public.bench.truth import read_truth

    truth = {e.plant_id: e for e in read_truth(result.truth_path)}
    for plant_id in result.fix.neutralised:
        assert truth[plant_id].at_export_ref is False
    for plant_id in result.fix.auto_resolved:
        assert truth[plant_id].at_export_ref is True
    plain = fixture.build(0, "tiny", out=tmp_path / "g")
    assert plain.fix is None


def test_blind_spots_are_measured_per_kind(tmp_path: Path) -> None:
    code, output, out = _bench(tmp_path, "--seeds", "0", "--blind-spots")
    assert code == 0, output
    data = json.loads((out / "blind-spots-tiny-0.json").read_text())
    assert list(data["kinds"]) == [f"blind-{k}" for k in blind_spots.KINDS]
    assert all(v["plants"] == 1 for v in data["kinds"].values())
    assert data["kinds"]["blind-zipped-secret"]["detected"] == 0
    assert data["kinds"]["blind-split-secret"]["detected"] == 0


def test_medium_and_unavailable_flags_are_usage_errors(tmp_path: Path) -> None:
    out = tmp_path / "results"
    medium = runner.invoke(app, ["bench", "--seeds", "100", "--size", "medium", "--out", str(out)])
    assert medium.exit_code == 2
    for flag in (["--runtime"], ["--gitleaks", str(tmp_path)], ["--real-world-dir", "x"]):
        result = runner.invoke(
            app, ["bench", "--seeds", "0", "--size", "tiny", "--out", str(out), *flag]
        )
        assert result.exit_code == 2, flag


def test_bad_seed_spec_is_exit_2(tmp_path: Path) -> None:
    code, _output, _out = _bench(tmp_path, "--seeds", "6-2")
    assert code == 2


def test_gate_failure_exits_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bench_run, "DETERMINISTIC_GATE", 1.1)
    code, _output, out = _bench(tmp_path, "--seeds", "0", "--gate")
    assert code == 1
    assert json.loads((out / "synthetic-tiny-0.json").read_text())["gates_pass"] is False
    # Without --gate the run still reports but does not fail.
    code, _output, _out = _bench(tmp_path / "again", "--seeds", "0")
    assert code == 0


def test_demo_builds_scans_and_prints_where_the_reports_are(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    reports = tmp_path / "reports"
    result = runner.invoke(app, ["demo", "--report-dir", str(reports)])
    assert result.exit_code == 0, result.stdout + result.stderr
    assert "demo repository:" in result.stdout
    assert f"reports: {reports}" in result.stdout
    assert (reports / "report.json").exists() and (reports / "report.html").exists()
    report = json.loads((reports / "report.json").read_text())
    assert report["findings"]
    assert report["repo"]["name"] == "demo-repo"
    assert (scratch / next(p.name for p in scratch.iterdir()) / "demo-repo").is_dir()


def test_generic_entropy_default_sits_inside_the_tuned_plateau(tmp_path: Path) -> None:
    """ADR 0010: from 3.3 to 4.3 go-public's own detector finds every planted generic
    value on seeds 0-1 and flags no placeholder; the default keeps a margin inside."""
    from go_public.config import Config

    assert 3.3 < Config().secrets.generic_entropy < 4.3
    options = bench_run.BenchOptions(seed_spec="0,1", size="tiny", out=tmp_path, jobs=1)
    with bench_run.Workspace(options) as workspace:
        own = 0
        for seed in options.seeds:
            findings = workspace.scan(workspace.fixture(seed))
            own += sum(1 for f in findings if f.rule_id == "generic-entropy")
            assert not [f for f in findings if "YOUR_API_KEY" in f.preview]
        assert own == 4  # two planted generic values per tiny seed
