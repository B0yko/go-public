"""`bench/run.py`: seed specs, gates, results-file sanitisation, location groups."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from go_public.bench import run as bench_run
from go_public.bench.match import ExpectedHit
from go_public.errors import UsageError


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("2-6", [2, 3, 4, 5, 6]),
        ("0,1", [0, 1]),
        ("100", [100]),
        ("0-1,5", [0, 1, 5]),
        ("3,3-4", [3, 4]),
        (" 7 ", [7]),
    ],
)
def test_parse_seeds(spec: str, expected: list[int]) -> None:
    assert bench_run.parse_seeds(spec) == expected


@pytest.mark.parametrize("spec", ["", "6-2", "a", "1-2-3", "-1", "1,,2", "1-"])
def test_parse_seeds_rejects_bad_specs(spec: str) -> None:
    with pytest.raises(UsageError):
        bench_run.parse_seeds(spec)


def test_results_file_labels() -> None:
    assert bench_run.seed_label("2-6") == "2-6"
    assert bench_run.seed_label("0,1") == "0_1"
    options = bench_run.BenchOptions(seed_spec="2-6", size="small", out=Path("x"))
    assert options.label == "small-2-6"
    assert options.command("--compare-head-only") == (
        "go-public bench --seeds 2-6 --size small --compare-head-only"
    )


def test_gate_thresholds() -> None:
    assert bench_run.gate_threshold("secret-generic") == 0.85
    assert bench_run.gate_threshold("pii-phone") == 0.85
    for cls in bench_run.EVAL_CLASSES:
        if cls not in ("secret-generic", "pii-phone"):
            assert bench_run.gate_threshold(cls) == 0.95


def test_sanitiser_rejects_absolute_paths_home_and_host() -> None:
    bench_run.assert_sanitised("clean text with paths like src/a.py and a ratio 0.95")
    for bad in (
        "wrote /Us" + "ers/someone/results.json",
        'path": "/home/runner/work"',
        "in (/private***REMOVED***)",
        "tmp=/tmp/go-public-bench-abc",
    ):
        with pytest.raises(bench_run.BenchError):
            bench_run.assert_sanitised(bad)
    with pytest.raises(bench_run.BenchError):
        bench_run.assert_sanitised(f"measured on {Path.home()}")
    host = socket.gethostname().split(".")[0]
    if len(host) >= 3:
        with pytest.raises(bench_run.BenchError):
            bench_run.assert_sanitised(f"host {host}")
    with pytest.raises(bench_run.BenchError):
        bench_run.assert_sanitised("has token-xyz-dir", extra=("token-xyz-dir",))


def _hit(location_type: str, kind: str = "blob") -> ExpectedHit:
    return ExpectedHit(
        plant_id="p",
        location_type=location_type,
        at_export_ref=False,
        eval_class="x",
        category="secret",
        kind=kind,
        key=("k",),
        matched=True,
    )


def test_location_groups_cover_every_location_type() -> None:
    from go_public.bench.plants import LOCATION_TYPES

    for location_type in LOCATION_TYPES:
        assert bench_run.location_group(_hit(location_type)) in bench_run.LOCATION_GROUPS
    assert bench_run.location_group(_hit("head", kind="identity")) == "identities"
    assert bench_run.location_group(_hit("stash")) == "notes/stash/remote/replace/original"
    assert bench_run.location_group(_hit("tag_message")) == "messages"


def test_default_hardware_is_a_label_not_a_host() -> None:
    label = bench_run.default_hardware()
    assert label in (bench_run.STUDIO_HARDWARE, bench_run.UNKNOWN_HARDWARE)
