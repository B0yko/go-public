"""`go-public bench --runtime`: wall time and peak memory of a full scan.

Every measurement runs the real command line (`python -m go_public scan <repo>
--include-unreachable ...`, `export --squash`) as a child under `/usr/bin/time -l`, so
interpreter start-up, the worker pool and report writing all count, exactly as a user
would see them. Each configuration runs `repeat` times and the median is reported.

Peak RSS is the `maximum resident set size` line of `/usr/bin/time -l`: the largest
resident set of any single process in the tree (the parent or one scan worker), not the
sum over the workers. The machine's load average at the start and end of every run is
recorded too, since other jobs share the machine.

Targets: the synthetic `medium` fixture (`run.py` builds it) and any extra repository
passed as a `RuntimeTarget` (the real-world clone of `pallets/flask`).
"""

from __future__ import annotations

import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from go_public.errors import GoPublicError

#: Target of the product spec: a full scan of synthetic `medium` in this many seconds.
TARGET_SECONDS = 60.0

_TIME_BIN = "/usr/bin/time"
_REAL_RE = re.compile(r"^\s*([0-9.]+)\s+real\b", re.MULTILINE)
_RSS_RE = re.compile(r"^\s*(\d+)\s+maximum resident set size\b", re.MULTILINE)


class RuntimeBenchError(GoPublicError):
    exit_code = 1


@dataclass(frozen=True)
class RuntimeTarget:
    """A repository to time. `config` is a go-public config (the fixture's own for
    synthetic targets); `None` means the built-in defaults. `facts` are extra items
    for the results file (tag, commit id, clone size), never paths."""

    label: str
    repo: Path
    config: Path | None = None
    export: bool = False
    #: True for the target the product's runtime target applies to (synthetic `medium`).
    gated: bool = False
    facts: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Measurement:
    wall_s: float
    rss_bytes: int
    load_start: float
    load_end: float


def parse_time_output(stderr: str) -> tuple[float, int]:
    """(real seconds, maximum resident set size in bytes) from BSD `time -l` output."""
    real = _REAL_RE.search(stderr)
    rss = _RSS_RE.search(stderr)
    if real is None or rss is None:
        raise RuntimeBenchError(
            "could not read `/usr/bin/time -l` output (the runtime bench needs the BSD/macOS time)"
        )
    return float(real.group(1)), int(rss.group(1))


def _child_env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GO_PUBLIC_"))}
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / "config")
    env["XDG_STATE_HOME"] = str(home / "state")
    return env


def measure(argv: Sequence[str], env: dict[str, str], *, ok_codes: tuple[int, ...]) -> Measurement:
    """Run `argv` under `/usr/bin/time -l`; exit codes outside `ok_codes` are errors."""
    load_start = os.getloadavg()[0]
    proc = subprocess.run(
        [_TIME_BIN, "-l", *argv],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    load_end = os.getloadavg()[0]
    if proc.returncode not in ok_codes:
        tail = "\n".join(proc.stderr.strip().splitlines()[-5:])
        raise RuntimeBenchError(
            f"command exited {proc.returncode} during the runtime bench: {tail}"
        )
    wall, rss = parse_time_output(proc.stderr)
    return Measurement(wall_s=wall, rss_bytes=rss, load_start=load_start, load_end=load_end)


def _median(values: list[float]) -> float:
    return float(statistics.median(values))


def _summary(runs: list[Measurement]) -> dict[str, Any]:
    return {
        "wall_s_median": round(_median([r.wall_s for r in runs]), 2),
        "wall_s_runs": [round(r.wall_s, 2) for r in runs],
        "peak_rss_mb_median": round(_median([r.rss_bytes / 1_000_000 for r in runs]), 1),
        "peak_rss_mb_runs": [round(r.rss_bytes / 1_000_000, 1) for r in runs],
        "load_avg_start": [round(r.load_start, 2) for r in runs],
        "load_avg_end": [round(r.load_end, 2) for r in runs],
    }


def _scan_argv(target: RuntimeTarget, jobs: int, report_dir: Path) -> list[str]:
    argv = [
        sys.executable,
        "-m",
        "go_public",
        "scan",
        str(target.repo),
        "--include-unreachable",
        "--quiet",
        "--report-dir",
        str(report_dir),
    ]
    if target.config is not None:
        argv += ["--config", str(target.config)]
    if jobs > 0:
        argv += ["--jobs", str(jobs)]
    return argv


def _export_argv(target: RuntimeTarget, out: Path, report_dir: Path) -> list[str]:
    argv = [
        sys.executable,
        "-m",
        "go_public",
        "export",
        str(target.repo),
        "--squash",
        "--out",
        str(out),
        "--report-dir",
        str(report_dir),
    ]
    if target.config is not None:
        argv += ["--config", str(target.config)]
    return argv


def _inventory(report_dir: Path) -> dict[str, Any]:
    """Counts from the last scan's `report.json` (which the scan just wrote)."""
    report = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
    inv = report["inventory"]
    refs = inv["ref_list"]
    return {
        "commits": inv["commits"],
        "branches": sum(1 for r in refs if r.startswith("refs/heads/")),
        "tags": sum(1 for r in refs if r.startswith("refs/tags/")),
        "annotated_tags": inv["tags"],
        "unique_blobs": inv["unique_blobs"],
        "total_blob_bytes": inv["total_bytes"],
        "unreachable_blobs": inv["unreachable_blobs"],
        "scan_duration_s": report["scan"]["duration_s"],
        "findings": len(report["findings"]),
    }


def _measure_scan(
    target: RuntimeTarget, *, jobs: int, repeat: int, tmp: Path, log: Callable[[str], None]
) -> dict[str, Any]:
    env = _child_env(tmp / "home")
    runs: list[Measurement] = []
    inventory: dict[str, Any] = {}
    for i in range(repeat):
        report_dir = tmp / f"reports-{jobs}-{i}"
        # Exit 1 is "findings at or above fail_on", still a completed scan.
        run = measure(_scan_argv(target, jobs, report_dir), env, ok_codes=(0, 1))
        runs.append(run)
        inventory = _inventory(report_dir)
        log(f"  scan jobs={jobs or 'default'} run {i + 1}/{repeat}: {run.wall_s:.2f} s")
    summary = _summary(runs)
    blobs = inventory["unique_blobs"]
    summary["blobs_per_s"] = round(blobs / summary["wall_s_median"], 1)
    summary["jobs"] = jobs or "default"
    summary["inventory"] = inventory
    return summary


def _measure_export(
    target: RuntimeTarget, *, repeat: int, tmp: Path, log: Callable[[str], None]
) -> dict[str, Any]:
    env = _child_env(tmp / "home")
    runs: list[Measurement] = []
    for i in range(repeat):
        # Exit 1 = export refused or NOT CLEAN; the time is still the time of the command.
        run = measure(
            _export_argv(target, tmp / f"export-{i}", tmp / f"export-reports-{i}"),
            env,
            ok_codes=(0,),
        )
        runs.append(run)
        log(f"  squash export run {i + 1}/{repeat}: {run.wall_s:.2f} s")
    return _summary(runs)


def run_runtime(
    targets: Sequence[RuntimeTarget],
    *,
    repeat: int,
    default_jobs: int = 0,
    log: Callable[[str], None] = lambda _line: None,
) -> dict[str, Any]:
    """Time every target (default `--jobs` and `--jobs 1`, and a squash export where the
    target asks for it). `default_jobs` > 0 pins what "default" means; 0 leaves the CLI
    default (CPU count)."""
    if repeat < 1:
        raise RuntimeBenchError("--repeat must be at least 1")
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="go-public-runtime-") as tmp_name:
        tmp = Path(tmp_name)
        (tmp / "home").mkdir()
        for index, target in enumerate(targets):
            log(f"{target.label}:")
            target_tmp = tmp / f"t{index}"
            target_tmp.mkdir()
            (target_tmp / "home").mkdir()
            entry: dict[str, Any] = {"label": target.label, "gated": target.gated, **target.facts}
            entry["scan_default_jobs"] = _measure_scan(
                target, jobs=default_jobs, repeat=repeat, tmp=target_tmp, log=log
            )
            entry["scan_jobs_1"] = _measure_scan(
                target, jobs=1, repeat=repeat, tmp=target_tmp, log=log
            )
            if target.export:
                entry["squash_export"] = _measure_export(
                    target, repeat=repeat, tmp=target_tmp, log=log
                )
            results.append(entry)
    return {"repeat": repeat, "target_seconds": TARGET_SECONDS, "targets": results}


# -- markdown ------------------------------------------------------------------------


def _mb(nbytes: int) -> str:
    return f"{nbytes / 1_000_000:.0f} MB"


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return "\n".join(lines)


def runtime_markdown(data: dict[str, Any], meta_block: str) -> str:
    out = ["# go-public runtime", "", meta_block, ""]
    out.append(
        f"Median of {data['repeat']} runs of the full command line under `/usr/bin/time -l`. "
        "Peak RSS is the largest single process (parent or one worker), not the sum over "
        "workers. Load average is the 1-minute figure at the start of each run; the machine "
        "is shared with other jobs."
    )
    out.append("")
    for target in data["targets"]:
        inv = target["scan_default_jobs"]["inventory"]
        out.append(f"## {target['label']}")
        out.append("")
        facts = ", ".join(
            f"{k.replace('_', ' ')}: {v}" for k, v in target.items() if k in _FACT_KEYS
        )
        shape = (
            f"{inv['commits']:,} commits, {inv['branches']} branches, {inv['tags']} tags "
            f"({inv.get('annotated_tags', 0)} annotated), "
            f"{inv['unique_blobs']:,} unique blobs, {_mb(inv['total_blob_bytes'])} of blob "
            f"content, {inv['unreachable_blobs']} unreachable blobs, {inv['findings']} findings"
        )
        out.append(shape + (f" ({facts})" if facts else "") + ".")
        out.append("")
        rows = []
        for key, name in (("scan_default_jobs", "default"), ("scan_jobs_1", "`--jobs 1`")):
            s = target[key]
            rows.append(
                [
                    f"scan, {name}",
                    f"{s['wall_s_median']:.2f}",
                    f"{s['peak_rss_mb_median']:.0f}",
                    f"{s['blobs_per_s']:.0f}",
                    ", ".join(f"{v:.1f}" for v in s["load_avg_start"]),
                ]
            )
        if "squash_export" in target:
            s = target["squash_export"]
            rows.append(
                [
                    "squash export",
                    f"{s['wall_s_median']:.2f}",
                    f"{s['peak_rss_mb_median']:.0f}",
                    "",
                    ", ".join(f"{v:.1f}" for v in s["load_avg_start"]),
                ]
            )
        out.append(_table(["Command", "Wall s", "Peak RSS MB", "Blobs/s", "Load avg"], rows))
        out.append("")
        wall = target["scan_default_jobs"]["wall_s_median"]
        if target["gated"]:
            verdict = "meets" if wall <= data["target_seconds"] else "misses"
            out.append(
                f"Full scan with the default `--jobs`: {wall:.2f} s, which {verdict} the "
                f"{data['target_seconds']:.0f} s target."
            )
            out.append("")
    return "\n".join(out)


_FACT_KEYS = frozenset({"tag", "tag_commit", "clone_size_mb"})
