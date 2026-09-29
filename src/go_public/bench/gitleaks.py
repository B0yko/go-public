"""`go-public bench --gitleaks <binary>`: the secrets baseline against gitleaks.

Secret plants only (the two secret eval classes of the truth files), by location type,
on the same fixtures go-public is scored on. Three ways of running gitleaks are compared
with go-public's own full scan:

- `gitleaks git`, all refs (`--log-opts=--all`): the history scanner, as documented.
- `gitleaks git` with replace refs ignored (`GIT_NO_REPLACE_OBJECTS=1`): the same command
  with git told not to follow `refs/replace/*`. gitleaks reads history through
  `git log -p`, which honours replace refs, so a fixture that carries one hides the
  replaced history from it; this variant separates that effect from real detection gaps.
- `gitleaks dir` over a checkout of `HEAD` (made through the export runner, `.git`
  removed): the external stand-in for a working-tree scanner.

All three run with gitleaks's default configuration and defaults for decoding
(`--max-decode-depth`) and archives (`--max-archive-depth`).

Locations that gitleaks's README does not claim to cover are "outside gitleaks's scope",
not misses: it documents scanning `git log -p` patches and directories or files, so
commit and tag messages, and objects no ref reaches (unreachable blobs), are outside it.
`gitleaks dir` sees a checkout only, so everything that is not at `HEAD` is outside a
checkout's scope by construction.

gitleaks reports a line and a file (and a commit in git mode); each finding is mapped
back to a truth key `(blob, line)` by resolving `commit:file` (git) or `HEAD:file` (dir)
to its blob id through the source runner.

go-public's secret rules are derived from gitleaks's, so differences below come from
coverage (locations, decoding, archives, generic detection), not from the patterns.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from go_public.bench import runtime as runtime_mod
from go_public.bench.match import ExpectedHit, expected_hits
from go_public.errors import GoPublicError
from go_public.git.runner import GitRunner

if TYPE_CHECKING:
    from go_public.bench.run import Fixture, Workspace

EXPECTED_VERSION = "8.30.1"
SECRET_CLASSES = frozenset({"secret-vendor", "secret-generic"})
#: Location types in table order, with why a location is outside gitleaks's documented scope
#: (None = inside it).
LOCATIONS: tuple[tuple[str, str | None], ...] = (
    ("head", None),
    ("history_only", None),
    ("side_branch", None),
    ("tag_only", None),
    ("notes", None),
    ("stash", None),
    ("remote_tracking", None),
    ("replace", None),
    ("original", None),
    ("path_name", "file names are matched only by its path rules, not by content rules"),
    ("commit_message", "commit messages are not part of the patches it scans"),
    ("tag_message", "tag messages are not part of the patches it scans"),
    ("unreachable", "objects no ref reaches are not in `git log`"),
)
_OUTSIDE = {name: why for name, why in LOCATIONS if why}
#: Kinds a gitleaks finding can never produce (no blob and line).
_UNMAPPABLE_KINDS = frozenset({"commit_message", "tag_message", "path"})
TIMING_REPEAT = 3

VARIANTS = ("git", "git_no_replace", "dir")
VARIANT_TITLES = {
    "git": "gitleaks git (all refs)",
    "git_no_replace": "gitleaks git (replace refs ignored)",
    "dir": "gitleaks dir (checkout of HEAD)",
}


class GitleaksError(GoPublicError):
    exit_code = 1


# -- running gitleaks --------------------------------------------------------------------


def _env(home: Path, *, no_replace: bool = False) -> dict[str, str]:
    env = {
        k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GITLEAKS_", "GO_PUBLIC_"))
    }
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / "config")
    env["XDG_STATE_HOME"] = str(home / "state")
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    if no_replace:
        env["GIT_NO_REPLACE_OBJECTS"] = "1"
    return env


def gitleaks_version(binary: Path) -> str:
    proc = subprocess.run(
        [str(binary), "version"], capture_output=True, text=True, check=False, timeout=30
    )
    return proc.stdout.strip() or proc.stderr.strip()


def command_line(variant: str, *extra: str) -> str:
    """The exact command, as recorded in the results (`<target>` and `<report>` stand
    for temporary paths)."""
    base = ["gitleaks", "dir"] if variant == "dir" else ["gitleaks", "git", "--log-opts=--all"]
    base += ["--no-banner", "--log-level", "error", "--exit-code", "0"]
    base += ["--report-format", "json", "--report-path", "<report>"]
    base += list(extra)
    base.append("<target>")
    prefix = "GIT_NO_REPLACE_OBJECTS=1 " if variant == "git_no_replace" else ""
    return prefix + " ".join(base)


@dataclass
class RunResult:
    wall_s: float
    findings: list[dict[str, Any]]


def run_gitleaks(
    binary: Path,
    variant: str,
    target: Path,
    home: Path,
    *extra: str,
) -> RunResult:
    report = home / "gitleaks-report.json"
    report.unlink(missing_ok=True)
    args = [str(binary)]
    args += ["dir"] if variant == "dir" else ["git", "--log-opts=--all"]
    args += ["--no-banner", "--log-level", "error", "--exit-code", "0"]
    args += ["--report-format", "json", "--report-path", str(report), *extra, str(target)]
    started = time.monotonic()
    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=False,
        env=_env(home, no_replace=variant == "git_no_replace"),
        stdin=subprocess.DEVNULL,
    )
    wall = time.monotonic() - started
    if proc.returncode != 0:
        tail = "\n".join(proc.stderr.strip().splitlines()[-3:])
        raise GitleaksError(f"gitleaks {variant} exited {proc.returncode}: {tail}")
    findings: list[dict[str, Any]] = []
    if report.exists() and report.stat().st_size:
        loaded = json.loads(report.read_text(encoding="utf-8"))
        if isinstance(loaded, list):
            findings = loaded
    return RunResult(wall_s=wall, findings=findings)


def checkout_head(source: Path, dest: Path) -> Path:
    """A working-tree copy of `source`'s HEAD without `.git`, made with the export runner."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="go-public-template-") as template:
        GitRunner(dest.parent, role="export").run(
            [
                "clone",
                "--no-local",
                "--single-branch",
                "--no-tags",
                f"--template={template}",
                str(source),
                str(dest),
            ]
        )
    shutil.rmtree(dest / ".git")
    return dest


# -- mapping findings to truth keys -------------------------------------------------------


def _blobs_for(runner: GitRunner, specs: list[str]) -> dict[str, str]:
    """`<rev>:<path>` -> blob id for every spec that resolves (one `cat-file --batch-check`)."""
    if not specs:
        return {}
    unique = sorted(set(specs))
    out = runner.run(
        ["cat-file", "--batch-check"], input=("\n".join(unique) + "\n").encode("utf-8")
    ).decode("utf-8", "replace")
    resolved: dict[str, str] = {}
    for spec, line in zip(unique, out.splitlines(), strict=True):
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "blob":
            resolved[spec] = parts[0]
    return resolved


def keys_from_git(runner: GitRunner, findings: list[dict[str, Any]]) -> set[tuple[str, int]]:
    """`(blob, line)` keys of gitleaks git findings (path-only rules carry no line)."""
    usable = [f for f in findings if f.get("StartLine") and "!" not in f["File"]]
    blobs = _blobs_for(runner, [f"{f['Commit']}:{f['File']}" for f in usable])
    return {
        (blobs[spec], f["StartLine"])
        for f in usable
        if (spec := f"{f['Commit']}:{f['File']}") in blobs
    }


def keys_from_dir(
    runner: GitRunner, checkout: Path, findings: list[dict[str, Any]]
) -> set[tuple[str, int]]:
    usable = []
    for f in findings:
        if not f.get("StartLine") or "!" in f["File"]:
            continue
        try:
            rel = Path(f["File"]).resolve().relative_to(checkout.resolve()).as_posix()
        except ValueError:
            continue
        usable.append((rel, f["StartLine"]))
    blobs = _blobs_for(runner, [f"HEAD:{rel}" for rel, _line in usable])
    return {(blobs[f"HEAD:{rel}"], line) for rel, line in usable if f"HEAD:{rel}" in blobs}


# -- scoring -----------------------------------------------------------------------------


@dataclass
class Tally:
    """Expected secret findings, by location type, for one tool."""

    found: Counter[str] = field(default_factory=Counter)
    found_by_class: Counter[str] = field(default_factory=Counter)
    found_ids: set[tuple[int, str, str]] = field(default_factory=set)


def _hit_key(seed: int, hit: ExpectedHit) -> tuple[int, str, str]:
    return (seed, hit.plant_id, repr(hit.key))


def _median(values: list[float]) -> float:
    return round(float(statistics.median(values)), 3)


def _time_gitleaks(
    binary: Path, variant: str, target: Path, home: Path, first: RunResult
) -> list[float]:
    walls = [first.wall_s]
    for _ in range(TIMING_REPEAT - 1):
        walls.append(run_gitleaks(binary, variant, target, home).wall_s)
    return walls


def _time_go_public(fx: Fixture, tmp: Path) -> list[float]:
    target = runtime_mod.RuntimeTarget(
        label="fixture", repo=fx.result.repo, config=fx.result.config_path
    )
    env = runtime_mod._child_env(tmp / "gp-home")
    walls = []
    for i in range(TIMING_REPEAT):
        argv = runtime_mod._scan_argv(target, 0, tmp / f"gp-report-{i}")
        started = time.monotonic()
        proc = subprocess.run(
            argv, capture_output=True, env=env, check=False, stdin=subprocess.DEVNULL
        )
        walls.append(time.monotonic() - started)
        if proc.returncode not in (0, 1):
            raise GitleaksError(f"go-public scan exited {proc.returncode} during the timing run")
    return walls


def run_gitleaks_baseline(workspace: Workspace, binary: Path) -> tuple[dict[str, Any], str]:
    """Score gitleaks and go-public on the secret plants of every seed, then time them."""
    from go_public.bench import run as bench_run  # local: run imports this module

    options = workspace.options
    version = gitleaks_version(binary)
    if version != EXPECTED_VERSION:
        raise GitleaksError(f"expected gitleaks {EXPECTED_VERSION}, found {version or 'nothing'}")
    home = workspace.root / "gitleaks-home"
    home.mkdir()

    tools: dict[str, Tally] = {name: Tally() for name in (*VARIANTS, "go_public")}
    total: Counter[str] = Counter()
    total_by_class: Counter[str] = Counter()
    per_location_class: defaultdict[str, Counter[str]] = defaultdict(Counter)
    walls: dict[str, list[float]] = {name: [] for name in (*VARIANTS, "go_public")}
    raw_counts: dict[str, int] = {name: 0 for name in VARIANTS}
    all_hits: dict[tuple[int, str, str], ExpectedHit] = {}

    for seed in options.seeds:
        fx = workspace.fixture(seed)
        hits = [
            h
            for h in expected_hits(fx.truth, workspace.scan(fx), eval_classes=set(SECRET_CLASSES))
            if h.category == "secret"
        ]
        runner = GitRunner(fx.result.repo, role="source")
        checkout = checkout_head(fx.result.repo, workspace.root / f"checkout-{seed}")
        runs = {
            "git": run_gitleaks(binary, "git", fx.result.repo, home),
            "git_no_replace": run_gitleaks(binary, "git_no_replace", fx.result.repo, home),
            "dir": run_gitleaks(binary, "dir", checkout, home),
        }
        found_keys = {
            "git": keys_from_git(runner, runs["git"].findings),
            "git_no_replace": keys_from_git(runner, runs["git_no_replace"].findings),
            "dir": keys_from_dir(runner, checkout, runs["dir"].findings),
        }
        for name, run in runs.items():
            raw_counts[name] += len(run.findings)
        for hit in hits:
            ident = _hit_key(seed, hit)
            all_hits[ident] = hit
            total[hit.location_type] += 1
            total_by_class[hit.eval_class] += 1
            per_location_class[hit.location_type][hit.eval_class] += 1
            for name in VARIANTS:
                if hit.kind in _UNMAPPABLE_KINDS:
                    continue
                if tuple(hit.key) in found_keys[name]:
                    _credit(tools[name], hit, ident)
            if hit.matched:
                _credit(tools["go_public"], hit, ident)
        for name in VARIANTS:
            target = checkout if name == "dir" else fx.result.repo
            walls[name] += _time_gitleaks(binary, name, target, home, runs[name])
        walls["go_public"] += _time_go_public(fx, workspace.root)

    blind = _blind_spot_secrets(workspace, binary, home)
    data = _assemble(
        options,
        version=version,
        total=total,
        total_by_class=total_by_class,
        tools=tools,
        walls=walls,
        raw_counts=raw_counts,
        all_hits=all_hits,
        blind=blind,
    )
    return data, _markdown(data, bench_run._meta_block(data["meta"]))


def _credit(tally: Tally, hit: ExpectedHit, ident: tuple[int, str, str]) -> None:
    tally.found[hit.location_type] += 1
    tally.found_by_class[hit.eval_class] += 1
    tally.found_ids.add(ident)


# -- blind-spot secrets ------------------------------------------------------------------

_BLIND_SECRET_KINDS = ("split-secret", "base64-secret", "zipped-secret", "minified-generic")


def _blind_spot_secrets(workspace: Workspace, binary: Path, home: Path) -> dict[str, Any]:
    """The four blind-spot plants that hold a secret, against go-public and against
    gitleaks with its defaults and with archive scanning switched on."""
    options = workspace.options
    planted: Counter[str] = Counter()
    found: defaultdict[str, Counter[str]] = defaultdict(Counter)
    for seed in options.seeds:
        fx = workspace.fixture(seed, plants=False, blind=True)
        runner = GitRunner(fx.result.repo, role="source")
        checkout = checkout_head(fx.result.repo, workspace.root / f"blind-checkout-{seed}")
        go_findings = workspace.scan(fx)
        runs = {
            "gitleaks git": (
                "git",
                run_gitleaks(binary, "git", fx.result.repo, home).findings,
            ),
            "gitleaks dir": ("dir", run_gitleaks(binary, "dir", checkout, home).findings),
            "gitleaks dir, --max-archive-depth 2": (
                "dir",
                run_gitleaks(binary, "dir", checkout, home, "--max-archive-depth", "2").findings,
            ),
        }
        blobs_by_tool: dict[str, set[str]] = {}
        for name, (variant, findings) in runs.items():
            if variant == "dir":
                blobs_by_tool[name] = {
                    blob for blob, _ in keys_from_dir_any_line(runner, checkout, findings)
                }
            else:
                blobs_by_tool[name] = {blob for blob, _ in keys_from_git_any_line(runner, findings)}
        for entry in fx.blind_truth:
            kind = (entry.eval_class or entry.plant_id).removeprefix("blind-")
            if kind not in _BLIND_SECRET_KINDS:
                continue
            blob = entry.expected[0].key["blob"]
            planted[kind] += 1
            if any(f.category == "secret" and f.location.blob == blob for f in go_findings):
                found[kind]["go-public"] += 1
            for name, blobs in blobs_by_tool.items():
                if blob in blobs:
                    found[kind][name] += 1
    tools = ["go-public", "gitleaks git", "gitleaks dir", "gitleaks dir, --max-archive-depth 2"]
    return {
        "kinds": {
            kind: {
                "plants": planted[kind],
                "found": {t: found[kind][t] for t in tools},
            }
            for kind in _BLIND_SECRET_KINDS
        },
        "tools": tools,
    }


def keys_from_git_any_line(
    runner: GitRunner, findings: list[dict[str, Any]]
) -> set[tuple[str, int]]:
    """Like `keys_from_git`, but archive members count (the file part before `!`) and the
    line is not required: a blind-spot plant is matched on its blob alone."""
    usable = [f for f in findings if f.get("File")]
    blobs = _blobs_for(runner, [f"{f['Commit']}:{f['File'].split('!')[0]}" for f in usable])
    return {
        (blobs[spec], f.get("StartLine") or 0)
        for f in usable
        if (spec := f"{f['Commit']}:{f['File'].split('!')[0]}") in blobs
    }


def keys_from_dir_any_line(
    runner: GitRunner, checkout: Path, findings: list[dict[str, Any]]
) -> set[tuple[str, int]]:
    usable = []
    for f in findings:
        try:
            rel = Path(f["File"].split("!")[0]).resolve().relative_to(checkout.resolve()).as_posix()
        except ValueError:
            continue
        usable.append((rel, f.get("StartLine") or 0))
    blobs = _blobs_for(runner, [f"HEAD:{rel}" for rel, _ in usable])
    return {(blobs[f"HEAD:{rel}"], line) for rel, line in usable if f"HEAD:{rel}" in blobs}


# -- results -----------------------------------------------------------------------------


def _ratio(found: int, plants: int) -> float | None:
    return round(found / plants, 4) if plants else None


def _assemble(
    options: Any,
    *,
    version: str,
    total: Counter[str],
    total_by_class: Counter[str],
    tools: dict[str, Tally],
    walls: dict[str, list[float]],
    raw_counts: dict[str, int],
    all_hits: dict[tuple[int, str, str], ExpectedHit],
    blind: dict[str, Any],
) -> dict[str, Any]:
    meta = options.metadata("gitleaks", "--gitleaks <gitleaks-binary>")
    meta["gitleaks_version"] = version
    locations = []
    for name, why in LOCATIONS:
        row: dict[str, Any] = {
            "location": name,
            "expected": total[name],
            "outside_gitleaks_scope": why,
            "go_public": tools["go_public"].found[name],
        }
        for variant in VARIANTS:
            row[variant] = tools[variant].found[name]
        locations.append(row)
    in_scope = sum(total[n] for n, why in LOCATIONS if why is None)
    head_total = total["head"]
    summary: dict[str, Any] = {
        "expected": sum(total.values()),
        "expected_in_gitleaks_git_scope": in_scope,
        "expected_at_head": head_total,
        "by_class": dict(total_by_class),
    }
    for name in ("go_public", *VARIANTS):
        t = tools[name]
        found_all = sum(t.found.values())
        found_scope = sum(t.found[n] for n, why in LOCATIONS if why is None)
        summary[name] = {
            "found": found_all,
            "recall_all": _ratio(found_all, summary["expected"]),
            "recall_in_git_scope": _ratio(found_scope, in_scope),
            "recall_at_head": _ratio(t.found["head"], head_total),
            "by_class": {
                cls: {
                    "found": t.found_by_class[cls],
                    "expected": total_by_class[cls],
                    "recall": _ratio(t.found_by_class[cls], total_by_class[cls]),
                }
                for cls in sorted(total_by_class)
            },
        }
    only_gitleaks = tools["git"].found_ids - tools["go_public"].found_ids
    only_go_public = tools["go_public"].found_ids - tools["git"].found_ids
    only_go_public_vs_nr = tools["go_public"].found_ids - tools["git_no_replace"].found_ids
    timing = {}
    for name, w in walls.items():
        per_fixture = [_median(w[i : i + TIMING_REPEAT]) for i in range(0, len(w), TIMING_REPEAT)]
        timing[name] = {
            "wall_s_median_per_fixture": _median(per_fixture),
            "wall_s_total_median": round(sum(per_fixture), 3),
            "runs_per_fixture": TIMING_REPEAT,
        }
    return {
        "schema": "go-public-bench-gitleaks-v1",
        "meta": meta,
        "commands": {
            "gitleaks_git": command_line("git"),
            "gitleaks_git_replace_refs_ignored": command_line("git_no_replace"),
            "gitleaks_dir": command_line("dir"),
            "gitleaks_dir_archives": command_line("dir", "--max-archive-depth", "2"),
            "go_public": "go-public scan <fixture> --include-unreachable --config <fixture-config>",
        },
        "locations": locations,
        "summary": summary,
        "gitleaks_only": _families(all_hits, only_gitleaks),
        "go_public_only": _families(all_hits, only_go_public),
        "go_public_only_vs_replace_ignored": _families(all_hits, only_go_public_vs_nr),
        "raw_findings": raw_counts,
        "timing": timing,
        "blind_spot_secrets": blind,
    }


def _families(
    all_hits: dict[tuple[int, str, str], ExpectedHit], idents: set[tuple[int, str, str]]
) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for ident in idents:
        hit = all_hits[ident]
        counts[f"{hit.eval_class}:{hit.location_type}"] += 1
    return dict(sorted(counts.items()))


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.3f}"


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return "\n".join(lines)


def _markdown(data: dict[str, Any], meta_block: str) -> str:
    meta = data["meta"]
    s = data["summary"]
    out = [
        "# Secrets baseline: go-public against gitleaks",
        "",
        meta_block,
        f"- gitleaks: {meta['gitleaks_version']} (official darwin_arm64 release, default config)",
        "",
        "Secret plants only (vendor-format and generic), on the same fixtures for both tools. "
        "The unit is an expected secret finding from the truth file. go-public's secret "
        "rules are derived from gitleaks's, so the differences below come from coverage "
        "(locations, decoding, archives, generic detection), not from the patterns.",
        "",
        "## Commands",
        "",
    ]
    for label, cmd in data["commands"].items():
        out.append(f"- {label.replace('_', ' ')}: `{cmd}`")
    out += [
        "",
        "A location is *outside gitleaks's scope* when its README does not claim to cover it: "
        "it scans `git log -p` patches and directories or files, so commit messages, tag "
        "messages and unreachable objects are outside it. Those rows are not counted as "
        "misses in the in-scope recall. `gitleaks dir` sees a checkout only, so only the "
        "`head` row is in its scope.",
        "",
        "## Recall by location type",
        "",
    ]
    rows = []
    for r in data["locations"]:
        outside = " (outside scope)" if r["outside_gitleaks_scope"] else ""
        checkout_note = "" if r["location"] == "head" else " (not in a checkout)"
        n = r["expected"]
        rows.append(
            [
                r["location"],
                n,
                f"{r['go_public']}/{n}",
                f"{r['git']}/{n}{outside}",
                f"{r['git_no_replace']}/{n}{outside}",
                f"{r['dir']}/{n}{checkout_note}",
            ]
        )
    out.append(
        _table(
            [
                "Location",
                "Expected",
                "go-public",
                VARIANT_TITLES["git"],
                VARIANT_TITLES["git_no_replace"],
                VARIANT_TITLES["dir"],
            ],
            rows,
        )
    )
    out += ["", "## Recall", ""]
    rows = []
    for name, title in (("go_public", "go-public (full scan)"), *VARIANT_TITLES.items()):
        t = s[name]
        rows.append(
            [
                title,
                f"{t['found']}/{s['expected']}",
                _pct(t["recall_all"]),
                _pct(t["recall_in_git_scope"]),
                _pct(t["recall_at_head"]),
            ]
        )
    out.append(
        _table(
            [
                "Tool",
                "Found",
                "Recall, all expected",
                f"Recall, gitleaks git scope ({s['expected_in_gitleaks_git_scope']})",
                f"Recall at HEAD ({s['expected_at_head']})",
            ],
            rows,
        )
    )
    out += ["", "By class:", ""]
    classes = sorted(s["by_class"])
    rows = [
        [
            title,
            *[
                f"{s[name]['by_class'][c]['found']}/{s[name]['by_class'][c]['expected']}"
                for c in classes
            ],
        ]
        for name, title in (("go_public", "go-public"), *VARIANT_TITLES.items())
    ]
    out.append(_table(["Tool", *classes], rows))
    out += ["", "## Wall time", ""]
    rows = [
        [
            title,
            f"{data['timing'][name]['wall_s_total_median']:.2f}",
            f"{data['timing'][name]['wall_s_median_per_fixture']:.2f}",
        ]
        for name, title in (
            ("go_public", "go-public scan (CLI, default jobs)"),
            *VARIANT_TITLES.items(),
        )
    ]
    out.append(_table(["Tool", "Total over fixtures, s", "Median per fixture, s"], rows))
    out += [
        "",
        f"Median of {TIMING_REPEAT} runs per fixture; go-public's time includes interpreter "
        "start-up and report writing, which dominate on fixtures this small.",
        "",
        "## Where the tools differ",
        "",
    ]
    only_g = data["gitleaks_only"]
    only_p = data["go_public_only"]
    out.append(
        "Expected findings found by gitleaks git but not by go-public: "
        + (", ".join(f"{k} ({v})" for k, v in only_g.items()) if only_g else "none")
        + "."
    )
    out.append("")
    out.append(
        "Expected findings found by go-public but not by gitleaks git: "
        + (", ".join(f"{k} ({v})" for k, v in only_p.items()) if only_p else "none")
        + "."
    )
    out.append("")
    only_nr = data["go_public_only_vs_replace_ignored"]
    out.append(
        "The same, against gitleaks git with replace refs ignored (what remains is coverage, "
        "not the replace-ref effect): "
        + (", ".join(f"{k} ({v})" for k, v in only_nr.items()) if only_nr else "none")
        + "."
    )
    blind = data["blind_spot_secrets"]
    out += [
        "",
        "## Blind-spot secrets",
        "",
        "The four blind-spot plants that hold a secret (built without the main plant set), "
        "matched on their blob. gitleaks decodes base64, hex and percent-encoding by "
        "default (`--max-decode-depth`) and can open archives with `--max-archive-depth`, "
        "which go-public does not do.",
        "",
    ]
    rows = []
    for kind, r in blind["kinds"].items():
        rows.append(
            [kind, r["plants"], *[f"{r['found'][t]}/{r['plants']}" for t in blind["tools"]]]
        )
    out.append(_table(["Blind spot", "Plants", *blind["tools"]], rows))
    out.append("")
    return "\n".join(out)
