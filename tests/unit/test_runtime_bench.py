"""`bench/runtime.py`: parsing `/usr/bin/time -l`, the results shape and the flask hook."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from go_public.bench import fixture as fixture_mod
from go_public.bench import runtime as rt
from go_public.errors import UsageError

_SAMPLE = """\
        3.27 real        10.90 user         1.20 sys
           182337536  maximum resident set size
                   0  average shared memory size
"""


def _bsd_time_available() -> bool:
    try:
        proc = subprocess.run(
            ["/usr/bin/time", "-l", "true"], capture_output=True, text=True, check=False
        )
    except OSError:
        return False
    return proc.returncode == 0 and "maximum resident set size" in proc.stderr


needs_bsd_time = pytest.mark.skipif(not _bsd_time_available(), reason="needs BSD time -l")


def test_parse_time_output() -> None:
    assert rt.parse_time_output(_SAMPLE) == (3.27, 182337536)


def test_parse_time_output_rejects_other_formats() -> None:
    with pytest.raises(rt.RuntimeBenchError):
        rt.parse_time_output("Maximum resident set size (kbytes): 1234\n")


def test_markdown_states_the_target_only_for_gated_targets() -> None:
    def scan(wall: float) -> dict[str, object]:
        return {
            "wall_s_median": wall,
            "peak_rss_mb_median": 100.0,
            "blobs_per_s": 10.0,
            "load_avg_start": [1.0],
            "inventory": {
                "commits": 3,
                "branches": 1,
                "tags": 0,
                "unique_blobs": 5,
                "total_blob_bytes": 1000,
                "unreachable_blobs": 0,
                "findings": 0,
            },
        }

    def target(label: str, gated: bool, wall: float) -> dict[str, object]:
        return {
            "label": label,
            "gated": gated,
            "scan_default_jobs": scan(wall),
            "scan_jobs_1": scan(wall * 2),
        }

    data = {
        "repeat": 3,
        "target_seconds": 60.0,
        "targets": [target("medium", True, 61.0), target("other", False, 90.0)],
    }
    md = rt.runtime_markdown(data, "- meta")
    assert md.count("target.") == 1
    assert "misses the 60 s target" in md


def test_bench_runtime_rejects_other_sizes_and_modes(tmp_path: Path) -> None:
    from go_public.bench import run as bench_run

    options = bench_run.BenchOptions(seed_spec="100", size="tiny", out=tmp_path)
    with pytest.raises(UsageError):
        bench_run.run(options, runtime=True)
    options = bench_run.BenchOptions(seed_spec="100", size="medium", out=tmp_path)
    with pytest.raises(UsageError):
        bench_run.run(options, runtime=True, blind=True)


@needs_bsd_time
def test_run_runtime_on_a_small_medium_fixture_and_an_extra_target(tmp_path: Path) -> None:
    built = fixture_mod.build(100, "medium", plants=False, medium_scale=0.01, out=tmp_path / "fx")
    extra = rt.RuntimeTarget(
        label="Extra repository",
        repo=built.repo,
        config=built.config_path,
        facts={"tag": "v1"},
    )
    data = rt.run_runtime(
        [
            rt.RuntimeTarget(
                label="Synthetic",
                repo=built.repo,
                config=built.config_path,
                export=True,
                gated=True,
            ),
            extra,
        ],
        repeat=2,
        default_jobs=2,
    )
    first, second = data["targets"]
    assert first["gated"] is True and second["gated"] is False and second["tag"] == "v1"
    for key in ("scan_default_jobs", "scan_jobs_1"):
        scan = first[key]
        assert len(scan["wall_s_runs"]) == 2 and scan["wall_s_median"] > 0
        assert scan["peak_rss_mb_median"] > 10
        assert scan["inventory"]["commits"] > 20 and scan["inventory"]["findings"] == 0
        assert scan["blobs_per_s"] > 0
    assert "squash_export" in first and "squash_export" not in second
    assert first["squash_export"]["wall_s_median"] > 0
