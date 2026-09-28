"""`go-public bench`: build fixtures, scan them, and score the scan against the truth.

Modes (each writes `<out>/<mode>-<size>-<seeds>.{json,md}`; with no mode flag the
synthetic per-class table runs):

- synthetic: per eval class plant counts, expected findings, TP/FN/FP, pooled and
  per-seed-minimum recall and precision, and the publication gates.
- `--compare-head-only`: recall by location type, full scan against `--head-only`.
- `--export-verify`: scan, scripted fix at HEAD, export, re-scan, source immutability.
- `--blind-spots`: measured recall on the blind-spot plants.

Every fixture is built in a temporary directory outside the repository and removed
afterwards. Results files carry no absolute path, user name or host name; the writer
refuses to write text that does.
"""

from __future__ import annotations

import contextlib
import getpass
import hashlib
import json
import re
import socket
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from go_public import __version__, pipeline
from go_public.bench import fixture as fixture_mod
from go_public.bench.match import ExpectedHit, expected_hits, finding_key, match
from go_public.bench.plants import blind_spots
from go_public.bench.truth import TruthEntry, read_truth
from go_public.config import load_config
from go_public.errors import GoPublicError, UsageError
from go_public.export import history as history_mod
from go_public.export import squash as squash_mod
from go_public.git.runner import GitRunner, check_git_version
from go_public.model import Finding, Report, severity_rank
from go_public.scan import ScanOptions

#: The evaluated classes, in table order (architecture.md "Fixture & truth").
EVAL_CLASSES: tuple[str, ...] = (
    "secret-vendor",
    "secret-generic",
    "pii-email",
    "pii-phone",
    "pii-name",
    "org-identifier",
    "local-path",
    "network",
    "binary-metadata",
    "licence",
    "large-file",
    "sensitive-file",
    "internal-notes",
    "identity",
    "trailer",
)

#: Gate thresholds (product spec, "Evaluation" item 1).
DETERMINISTIC_GATE = 0.95
LOOSE_GATE = 0.85
LOOSE_CLASSES = frozenset({"secret-generic", "pii-phone"})

STUDIO_HARDWARE = "Mac Studio M4 Max, 128 GB"
#: Recorded when the machine model is unknown; pass `--hardware` to name it.
UNKNOWN_HARDWARE = "not recorded"


class BenchError(GoPublicError):
    """A bench run could not produce trustworthy results."""

    exit_code = 1


# -- seeds, metadata -----------------------------------------------------------------


def parse_seeds(spec: str) -> list[int]:
    """`"2-6"` -> [2..6]; `"0,1"` -> [0, 1]; `"100"` -> [100]; parts combine (`"0-1,5"`)."""
    seeds: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise UsageError(f"--seeds: empty entry in {spec!r}")
        bounds = part.split("-")
        try:
            if len(bounds) == 1:
                numbers = [int(bounds[0])]
            elif len(bounds) == 2:
                low, high = int(bounds[0]), int(bounds[1])
                if high < low:
                    raise UsageError(f"--seeds: descending range {part!r}")
                numbers = list(range(low, high + 1))
            else:
                raise ValueError(part)
        except ValueError:
            raise UsageError(f"--seeds: cannot parse {part!r} in {spec!r}") from None
        if any(n < 0 for n in numbers):
            raise UsageError(f"--seeds: negative seed in {spec!r}")
        seeds.extend(n for n in numbers if n not in seeds)
    return seeds


def seed_label(spec: str) -> str:
    """The part of a results file name that names the seeds (`2-6`, `0_1`, `100`)."""
    return re.sub(r"[^0-9-]+", "_", spec.strip())


def default_hardware() -> str:
    """The Studio label when this machine reports the Mac Studio (M4 Max) model id;
    never a host name."""
    try:
        model = subprocess.run(
            ["sysctl", "-n", "hw.model"], capture_output=True, text=True, timeout=5, check=False
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return UNKNOWN_HARDWARE
    return STUDIO_HARDWARE if model == "Mac16,9" else UNKNOWN_HARDWARE


@dataclass(frozen=True)
class BenchOptions:
    seed_spec: str
    size: str
    out: Path
    jobs: int = 0
    hardware: str = ""
    detector_commit: str = "unknown"
    #: Extra flags shown in the recorded reproduction command (no paths).
    flags: tuple[str, ...] = ()

    @property
    def seeds(self) -> list[int]:
        return parse_seeds(self.seed_spec)

    @property
    def label(self) -> str:
        return f"{self.size}-{seed_label(self.seed_spec)}"

    def command(self, *extra: str) -> str:
        parts = ["go-public", "bench", "--seeds", self.seed_spec, "--size", self.size]
        parts.extend([*self.flags, *extra])
        return " ".join(parts)

    def metadata(self, mode: str, *extra_flags: str) -> dict[str, Any]:
        return {
            "mode": mode,
            "date_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "hardware": self.hardware or default_hardware(),
            "git_version": check_git_version().removeprefix("git version "),
            "go_public_version": __version__,
            "detector_commit": self.detector_commit,
            "seeds": self.seeds,
            "size": self.size,
            "command": self.command(*extra_flags),
        }


# -- fixtures and scans --------------------------------------------------------------


@dataclass
class Fixture:
    seed: int
    key: tuple[int, bool, bool, bool]
    result: fixture_mod.FixtureResult
    truth: list[TruthEntry]
    blind_truth: list[TruthEntry] = field(default_factory=list)


class Workspace:
    """A temporary directory (outside the repository) holding fixtures and exports,
    with the scans memoised so several modes share one scan per fixture."""

    def __init__(self, options: BenchOptions) -> None:
        self.options = options
        self._tmp = tempfile.TemporaryDirectory(prefix="go-public-bench-")
        self.root = Path(self._tmp.name)
        self._fixtures: dict[tuple[int, bool, bool, bool], Fixture] = {}
        self._scans: dict[tuple[tuple[int, bool, bool, bool], bool], list[Finding]] = {}
        self.git_version = check_git_version()

    def close(self) -> None:
        self._tmp.cleanup()

    def __enter__(self) -> Workspace:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def fixture(
        self,
        seed: int,
        *,
        plants: bool = True,
        blind: bool = False,
        scripted_fix: bool = False,
    ) -> Fixture:
        key = (seed, plants, blind, scripted_fix)
        if key not in self._fixtures:
            out = self.root / f"fixture-{seed}-{int(plants)}{int(blind)}{int(scripted_fix)}"
            result = fixture_mod.build(
                seed,
                self.options.size,
                plants=plants,
                blind_spots=blind,
                scripted_fix=scripted_fix,
                out=out,
            )
            self._fixtures[key] = Fixture(
                seed=seed,
                key=key,
                result=result,
                truth=read_truth(result.truth_path),
                blind_truth=(
                    read_truth(result.blind_truth_path) if result.blind_truth_path else []
                ),
            )
        return self._fixtures[key]

    def scan(self, fx: Fixture, *, head_only: bool = False) -> list[Finding]:
        """Scan the fixture the way `go-public scan` does (`--include-unreachable`
        for a full scan), through the same pipeline."""
        key = (fx.key, head_only)
        if key not in self._scans:
            self._scans[key] = scan_repo(
                fx.result.repo,
                fx.result.config_path,
                jobs=self.options.jobs,
                head_only=head_only,
                git_version=self.git_version,
            )
        return self._scans[key]


def scan_repo(
    repo: Path,
    config_path: Path,
    *,
    jobs: int,
    head_only: bool,
    git_version: str,
) -> list[Finding]:
    config = load_config(config_path)
    runner = GitRunner(repo, role="source")
    assessment = pipeline.assess(
        runner,
        repo_path=repo,
        ref="HEAD",
        config=config,
        config_source="fixture",
        options=ScanOptions.from_config(config, jobs=jobs),
        git_version=git_version,
        fail_on="high",
        include_unreachable=not head_only,
        head_only=head_only,
    )
    return assessment.findings


# -- results files -------------------------------------------------------------------


def _forbidden_fragments() -> list[str]:
    fragments = {str(Path.home()), socket.gethostname(), socket.gethostname().split(".")[0]}
    with contextlib.suppress(KeyError, OSError):
        fragments.add(getpass.getuser())
    return [f for f in fragments if len(f) >= 3 and f not in ("/", "root")]


_ABS_PATH_RE = re.compile(
    r"(?:^|[\s\"'(=:,\[])/(?:Users|home|private|var|tmp|opt|Volumes|etc|usr)/", re.MULTILINE
)


def assert_sanitised(text: str, *, extra: tuple[str, ...] = ()) -> None:
    """Raise `BenchError` if `text` holds an absolute path, the user name, the home
    directory or the host name."""
    if _ABS_PATH_RE.search(text):
        raise BenchError("refusing to write a results file that contains an absolute path")
    for fragment in (*_forbidden_fragments(), *extra):
        if fragment and fragment in text:
            raise BenchError(
                "refusing to write a results file that contains a user, host or temp-dir name"
            )


def write_results(
    out: Path, stem: str, data: dict[str, Any], markdown: str, *, workspace: Workspace
) -> list[Path]:
    """Write `<stem>.json` and `<stem>.md` under `out` after the sanitisation check."""
    text_json = json.dumps(data, indent=2) + "\n"
    extra = (str(workspace.root),)
    assert_sanitised(text_json, extra=extra)
    assert_sanitised(markdown, extra=extra)
    out.mkdir(parents=True, exist_ok=True)
    paths = [out / f"{stem}.json", out / f"{stem}.md"]
    paths[0].write_text(text_json, encoding="utf-8")
    paths[1].write_text(markdown, encoding="utf-8")
    return paths


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return "\n".join(lines)


def _pct(value: float) -> str:
    return f"{value:.3f}"


def _meta_block(meta: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"- Date (UTC): {meta['date_utc']}",
            f"- Hardware: {meta['hardware']}",
            f"- git: {meta['git_version']}",
            f"- go-public: {meta['go_public_version']}",
            f"- Detector commit: {meta['detector_commit']}",
            f"- Size: {meta['size']}; seeds: {', '.join(str(s) for s in meta['seeds'])}",
            f"- Command: `{meta['command']}`",
        ]
    )


# -- synthetic table -----------------------------------------------------------------


@dataclass
class ClassTotals:
    plants: int = 0
    expected: int = 0
    tp: int = 0
    findings: int = 0
    matched_findings: int = 0
    seed_recalls: list[float] = field(default_factory=list)
    seed_precisions: list[float] = field(default_factory=list)

    @property
    def fn(self) -> int:
        return self.expected - self.tp

    @property
    def fp(self) -> int:
        return self.findings - self.matched_findings

    @property
    def recall(self) -> float:
        return 1.0 if self.expected == 0 else self.tp / self.expected

    @property
    def precision(self) -> float:
        return 1.0 if self.findings == 0 else self.matched_findings / self.findings


def gate_threshold(eval_class: str) -> float:
    return LOOSE_GATE if eval_class in LOOSE_CLASSES else DETERMINISTIC_GATE


def run_synthetic(workspace: Workspace) -> tuple[dict[str, Any], str, bool]:
    """Scan every seed's fixture and score it. Returns (json data, markdown, gates ok)."""
    options = workspace.options
    totals = {cls: ClassTotals() for cls in EVAL_CLASSES}
    per_seed: dict[str, dict[str, dict[str, Any]]] = {}
    failures: list[dict[str, Any]] = []
    classes = set(EVAL_CLASSES)
    for seed in options.seeds:
        fx = workspace.fixture(seed)
        findings = workspace.scan(fx)
        report = match(fx.truth, findings, eval_classes=classes)
        seed_rows: dict[str, dict[str, Any]] = {}
        for entry in fx.truth:
            if entry.eval_class in totals:
                totals[entry.eval_class].plants += 1
        for cls in EVAL_CLASSES:
            result = report.by_class.get(cls)
            total = totals[cls]
            if result is not None:
                total.expected += result.expected
                total.tp += result.matched_expected
                total.findings += result.findings
                total.matched_findings += result.matched_findings
                total.seed_recalls.append(result.recall)
                total.seed_precisions.append(result.precision)
                seed_rows[cls] = {
                    "expected": result.expected,
                    "tp": result.matched_expected,
                    "findings": result.findings,
                    "fp": result.findings - result.matched_findings,
                    "recall": round(result.recall, 4),
                    "precision": round(result.precision, 4),
                }
        per_seed[str(seed)] = seed_rows
        failures.extend(
            {"seed": seed, "type": "missed", "plant_id": pid, "eval_class": cls}
            for pid, cls in report.unmatched_expected
        )
        failures.extend(
            {
                "seed": seed,
                "type": "false-positive",
                "eval_class": f.category if f.category != "pii" else f.rule_id,
                "rule_id": f.rule_id,
                "location_kind": f.location.kind,
            }
            for f in report.unmatched_findings
        )

    classes_out: dict[str, dict[str, Any]] = {}
    all_pass = True
    for cls in EVAL_CLASSES:
        total = totals[cls]
        threshold = gate_threshold(cls)
        passed = total.recall >= threshold and total.precision >= threshold
        all_pass = all_pass and passed
        classes_out[cls] = {
            "plants": total.plants,
            "expected_findings": total.expected,
            "tp": total.tp,
            "fn": total.fn,
            "fp": total.fp,
            "findings": total.findings,
            "recall": round(total.recall, 4),
            "precision": round(total.precision, 4),
            "per_seed_min_recall": round(min(total.seed_recalls, default=1.0), 4),
            "per_seed_min_precision": round(min(total.seed_precisions, default=1.0), 4),
            "gate": threshold,
            "pass": passed,
        }
    data = {
        "schema": "go-public-bench-synthetic-v1",
        "meta": options.metadata("synthetic"),
        "classes": classes_out,
        "per_seed": per_seed,
        "failures": failures,
        "gates_pass": all_pass,
    }
    return data, _synthetic_markdown(data), all_pass


def _synthetic_markdown(data: dict[str, Any]) -> str:
    rows = []
    for cls, r in data["classes"].items():
        rows.append(
            [
                cls,
                r["plants"],
                r["expected_findings"],
                r["tp"],
                r["fn"],
                r["fp"],
                _pct(r["recall"]),
                _pct(r["precision"]),
                _pct(r["per_seed_min_recall"]),
                _pct(r["per_seed_min_precision"]),
                f">= {r['gate']:.2f}",
                "pass" if r["pass"] else "FAIL",
            ]
        )
    table = _table(
        [
            "Class",
            "Plants",
            "Expected",
            "TP",
            "FN",
            "FP",
            "Recall",
            "Precision",
            "Min seed recall",
            "Min seed precision",
            "Gate",
            "Result",
        ],
        rows,
    )
    verdict = "All gates pass." if data["gates_pass"] else "One or more gates FAILED."
    lines = [
        "# Synthetic bench: per-class recall and precision",
        "",
        _meta_block(data["meta"]),
        "",
        "Pooled counts over the listed seeds. A finding that matches no truth entry is a "
        "false positive in its own class; duplicates of one truth entry count once.",
        "",
        table,
        "",
        verdict,
    ]
    if data["failures"]:
        lines += ["", "## Misses and false positives", ""]
        lines.append(
            _table(
                ["Seed", "Type", "Class", "Detail"],
                [
                    [
                        f["seed"],
                        f["type"],
                        f["eval_class"],
                        f.get("plant_id") or f"{f.get('rule_id')} at {f.get('location_kind')}",
                    ]
                    for f in data["failures"]
                ],
            )
        )
    return "\n".join(lines) + "\n"


# -- recall by location type ---------------------------------------------------------

#: Location group for a truth entry (order = table order).
LOCATION_GROUPS: tuple[str, ...] = (
    "head",
    "binary fields",
    "history-only",
    "side branch",
    "tag",
    "notes/stash/remote/replace/original",
    "messages",
    "identities",
    "ref names",
    "licence transitions",
    "unreachable",
)

_LOCATION_TO_GROUP = {
    "head": "head",
    "path_name": "head",
    "binary_field": "binary fields",
    "history_only": "history-only",
    "side_branch": "side branch",
    "tag_only": "tag",
    "notes": "notes/stash/remote/replace/original",
    "stash": "notes/stash/remote/replace/original",
    "remote_tracking": "notes/stash/remote/replace/original",
    "replace": "notes/stash/remote/replace/original",
    "original": "notes/stash/remote/replace/original",
    "commit_message": "messages",
    "tag_message": "messages",
    "trailer": "messages",
    "ref_name": "ref names",
    "licence_transition": "licence transitions",
    "unreachable": "unreachable",
}


def location_group(hit: ExpectedHit) -> str:
    """Identity findings are their own group wherever the commit sits; every other
    expected finding is grouped by where its plant was placed."""
    if hit.kind == "identity":
        return "identities"
    return _LOCATION_TO_GROUP[hit.location_type]


def run_compare_head_only(workspace: Workspace) -> tuple[dict[str, Any], str]:
    options = workspace.options
    classes = set(EVAL_CLASSES)
    full: Counter[str] = Counter()
    head: Counter[str] = Counter()
    total: Counter[str] = Counter()
    for seed in options.seeds:
        fx = workspace.fixture(seed)
        full_hits = expected_hits(fx.truth, workspace.scan(fx), eval_classes=classes)
        head_hits = expected_hits(
            fx.truth, workspace.scan(fx, head_only=True), eval_classes=classes
        )
        for f_hit, h_hit in zip(full_hits, head_hits, strict=True):
            group = location_group(f_hit)
            total[group] += 1
            full[group] += f_hit.matched
            # A history-only plant whose text happens to equal a blob at HEAD (several
            # plants share content) is not "found" by a HEAD-only review: that review
            # sees a different planted issue, not this one.
            head[group] += h_hit.matched and h_hit.at_export_ref
    groups: dict[str, dict[str, Any]] = {}
    for group in LOCATION_GROUPS:
        if not total[group]:
            continue
        groups[group] = {
            "expected": total[group],
            "full_found": full[group],
            "head_only_found": head[group],
            "full_recall": round(full[group] / total[group], 4),
            "head_only_recall": round(head[group] / total[group], 4),
        }
    grand = sum(total.values())
    overall = {
        "expected": grand,
        "full_found": sum(full.values()),
        "head_only_found": sum(head.values()),
        "full_recall": round(sum(full.values()) / grand, 4) if grand else 1.0,
        "head_only_recall": round(sum(head.values()) / grand, 4) if grand else 1.0,
    }
    data: dict[str, Any] = {
        "schema": "go-public-bench-head-only-compare-v1",
        "meta": options.metadata("head-only-compare", "--compare-head-only"),
        "by_location": groups,
        "overall": overall,
    }
    rows = [
        [g, r["expected"], r["full_found"], _pct(r["full_recall"]), r["head_only_found"]]
        + [_pct(r["head_only_recall"])]
        for g, r in [*groups.items(), ("all locations", overall)]
    ]
    md = "\n".join(
        [
            "# Recall by location type: full scan against `--head-only`",
            "",
            _meta_block(data["meta"]),
            "",
            "`--head-only` scans only the export ref's tree, as a working-tree scanner "
            "would. Counts are expected findings from the truth files; a finding "
            "counts as found by `--head-only` only when the planted issue itself is "
            "at the export ref.",
            "",
            _table(
                [
                    "Location",
                    "Expected",
                    "Full found",
                    "Full recall",
                    "Head-only found",
                    "Head-only recall",
                ],
                rows,
            ),
        ]
    )
    return data, md + "\n"


# -- blind spots ---------------------------------------------------------------------


def run_blind_spots(workspace: Workspace) -> tuple[dict[str, Any], str]:
    options = workspace.options
    detected: Counter[str] = Counter()
    planted: Counter[str] = Counter()
    rules: defaultdict[str, Counter[str]] = defaultdict(Counter)
    for seed in options.seeds:
        fx = workspace.fixture(seed, plants=False, blind=True)
        findings = workspace.scan(fx)
        for entry in fx.blind_truth:
            kind = entry.eval_class or entry.plant_id
            planted[kind] += 1
            expected = entry.expected[0]
            blob = expected.key["blob"]
            hits = [
                f for f in findings if f.category == expected.category and f.location.blob == blob
            ]
            if hits:
                detected[kind] += 1
                for hit in hits:
                    rules[kind][hit.rule_id] += 1
    kinds: dict[str, dict[str, Any]] = {}
    for kind in (f"blind-{k}" for k in blind_spots.KINDS):
        kinds[kind] = {
            "plants": planted[kind],
            "detected": detected[kind],
            "recall": round(detected[kind] / planted[kind], 4) if planted[kind] else 0.0,
            "detected_by": sorted(rules[kind]),
        }
    plants = sum(planted.values())
    found = sum(detected.values())
    data: dict[str, Any] = {
        "schema": "go-public-bench-blind-spots-v1",
        "meta": options.metadata("blind-spots", "--blind-spots"),
        "kinds": kinds,
        "overall": {
            "plants": plants,
            "detected": found,
            "recall": round(found / plants, 4) if plants else 0.0,
        },
    }
    rows = [
        [
            k.removeprefix("blind-"),
            r["plants"],
            r["detected"],
            _pct(r["recall"]),
            ", ".join(r["detected_by"]) or "-",
        ]
        for k, r in kinds.items()
    ]
    md = "\n".join(
        [
            "# Blind spots: measured recall",
            "",
            _meta_block(data["meta"]),
            "",
            "Plants a static, offline scanner is not expected to catch, built without the "
            "main plant set. A plant counts as detected when a finding of the expected "
            "category sits on its blob.",
            "",
            _table(["Blind spot", "Plants", "Detected", "Recall", "Detected by"], rows),
            "",
            f"Overall: {found} of {plants} detected (recall {_pct(found / max(plants, 1))}).",
        ]
    )
    return data, md + "\n"


# -- export verification --------------------------------------------------------------


def repo_fingerprint(repo: Path) -> dict[str, object]:
    """Everything a read-only run must leave untouched (product spec item 17): refs,
    object counts, config/HEAD/packed-refs hashes, hook names and the object listing."""
    runner = GitRunner(repo, role="source")
    git_dir = repo / ".git" if (repo / ".git").exists() else repo

    def sha(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "absent"

    hooks = git_dir / "hooks"
    return {
        "refs": runner.run(["for-each-ref", "--format=%(refname) %(objectname)"]).decode(),
        "count": runner.run(["count-objects", "-v"]).decode(),
        "config": sha(git_dir / "config"),
        "head_file": sha(git_dir / "HEAD"),
        "index": sha(git_dir / "index"),
        "packed_refs": sha(git_dir / "packed-refs"),
        "hooks": sorted(p.name for p in hooks.glob("*")) if hooks.is_dir() else [],
        "objects": sorted(
            f"{p.relative_to(git_dir).as_posix()}:{p.stat().st_size}"
            for p in (git_dir / "objects").rglob("*")
            if p.is_file()
        ),
    }


@dataclass
class ExportOutcome:
    """What one export mode did to one fixture."""

    refused: bool
    clean: bool | None
    blocking: int
    findings: list[Finding]
    notes: list[str] = field(default_factory=list)
    #: Findings the mode leaves in place by design, by reason; they are not part of
    #: `findings`.
    by_design: dict[str, int] = field(default_factory=dict)
    #: Whether blob ids survive the export (squash) or change with the rewrite.
    stable_blob_ids: bool = True


ExportRunner = Callable[[Workspace, Fixture, Path], ExportOutcome]


def _export_squash(workspace: Workspace, fx: Fixture, work: Path) -> ExportOutcome:
    config = load_config(fx.result.config_path)
    log: list[str] = []
    author = squash_mod.parse_identity(config.export.author)
    request = squash_mod.SquashRequest(
        source=fx.result.repo,
        out=work / "export",
        ref="HEAD",
        config=config,
        config_source="fixture",
        scan_options=ScanOptions.from_config(config, jobs=workspace.options.jobs),
        git_version=workspace.git_version,
        fail_on="low",
        author=author,
        message=config.export.message,
        commit_date=squash_mod.resolve_commit_date(config.export.date),
        report_dir=work / "export-report",
    )
    result = squash_mod.run_squash(request, log.append)
    if result.out is None or "json" not in result.report_paths:
        return ExportOutcome(
            refused=True,
            clean=None,
            blocking=len(result.blocking),
            findings=[],
            notes=[f"{f.category}/{f.rule_id}" for f in result.blocking],
        )
    report = Report.model_validate_json(result.report_paths["json"].read_text(encoding="utf-8"))
    return ExportOutcome(
        refused=False, clean=result.clean, blocking=len(result.blocking), findings=report.findings
    )


def by_design_reason(finding: Finding) -> str | None:
    """Why a kept history still carries this finding, when it does by design: licence
    history is kept as it was, and only blobs at or above the size limit are dropped."""
    if history_mod.is_licence_history(finding):
        return "licence history"
    if finding.rule_id == "large-file-warn":
        return "large file below the size limit"
    if finding.rule_id == "lfs-pointer":
        return "LFS pointer"
    return None


def _export_keep_history(workspace: Workspace, fx: Fixture, work: Path) -> ExportOutcome:
    config = load_config(fx.result.config_path)
    log: list[str] = []
    request = history_mod.HistoryRequest(
        source=fx.result.repo,
        out=work / "export",
        ref="HEAD",
        config=config,
        config_source="fixture",
        scan_options=ScanOptions.from_config(config, jobs=workspace.options.jobs),
        git_version=workspace.git_version,
        fail_on="low",
        author=squash_mod.parse_identity(config.export.author),
        include_tags=True,
        report_dir=work / "export-report",
    )
    result = history_mod.run_history(request, log.append)
    if result.out is None or "json" not in result.report_paths:
        return ExportOutcome(
            refused=True,
            clean=None,
            blocking=len(result.blocking),
            findings=[],
            notes=[f"{f.category}/{f.rule_id}" for f in result.blocking],
            stable_blob_ids=False,
        )
    report = Report.model_validate_json(result.report_paths["json"].read_text(encoding="utf-8"))
    kept = [f for f in report.findings if by_design_reason(f) is None]
    by_design = Counter(r for f in report.findings if (r := by_design_reason(f)) is not None)
    # `clean` here means nothing but the by-design items remains at `--fail-on low`.
    clean = not any(severity_rank(f.severity) >= severity_rank("low") for f in kept)
    return ExportOutcome(
        refused=False,
        clean=clean,
        blocking=len(result.blocking),
        findings=kept,
        by_design=dict(by_design),
        stable_blob_ids=False,
    )


#: Export modes `--export-verify` runs, each with the same columns.
EXPORT_MODES: dict[str, ExportRunner] = {
    "squash": _export_squash,
    "keep-history": _export_keep_history,
}

_TREE_KINDS = frozenset({"blob", "path", "binary_field"})


def _stable_key(hit: ExpectedHit) -> tuple[str, Any] | None:
    """A key that survives an export: blob ids, paths and identity strings do not
    change; commit, tag and ref ids do."""
    if hit.kind in ("blob", "unreachable_blob", "binary_field", "path", "identity"):
        return (hit.category, hit.key)
    return None


def _finding_stable_keys(findings: list[Finding]) -> set[tuple[str, Any]]:
    keys: set[tuple[str, Any]] = set()
    for f in findings:
        loc = f.location
        if loc.kind in ("blob", "unreachable_blob"):
            keys.add((f.category, (loc.blob, loc.line)))
        elif loc.kind == "binary_field":
            keys.add((f.category, (loc.blob, loc.field)))
        elif loc.kind == "path" and loc.paths:
            keys.add((f.category, (loc.paths[0],)))
        elif loc.kind == "identity":
            keys.add((f.category, (loc.identity,)))
    return keys


_BLOB_KINDS = frozenset({"blob", "unreachable_blob", "binary_field"})


def _rewrite_residuals(
    before_findings: list[Finding],
    hits: list[ExpectedHit],
    history_hits: list[ExpectedHit],
    export_findings: list[Finding],
) -> tuple[int, int, int]:
    """`(history residual, residual true, residual false positives)` for an export whose
    blob ids changed (a rewritten history): blob findings are matched to the truth
    through their paths, paths and identities through their stable keys, and message-like
    findings through their category and location kind."""
    truth_keys = {(h.category, h.key) for h in hits}
    true_source = [
        f
        for f in before_findings
        if (key := finding_key(f)) is not None and (f.category, key) in truth_keys
    ]
    true_paths = {(f.category, p) for f in true_source for p in f.location.paths}
    true_kinds = {(f.category, f.location.kind) for f in true_source}
    paths_by_key: defaultdict[tuple[str, Any], set[str]] = defaultdict(set)
    for f in true_source:
        paths_by_key[(f.category, finding_key(f))].update(f.location.paths)
    export_paths = {(f.category, p) for f in export_findings for p in f.location.paths}
    export_kinds = {(f.category, f.location.kind) for f in export_findings}
    export_stable = _finding_stable_keys(export_findings)
    all_stable = {k for h in hits if (k := _stable_key(h)) is not None}

    history_residual = 0
    for h in history_hits:
        if h.kind in _BLOB_KINDS:
            gone = not any(
                (h.category, p) in export_paths for p in paths_by_key[(h.category, h.key)]
            )
        elif (stable := _stable_key(h)) is not None:
            gone = stable not in export_stable
        else:
            gone = (h.category, h.kind) not in export_kinds
        history_residual += 0 if gone else 1

    residual_true = residual_fp = 0
    for f in export_findings:
        kind = f.location.kind
        if kind in _BLOB_KINDS:
            is_true = any((f.category, p) in true_paths for p in f.location.paths)
        elif kind in ("path", "identity"):
            is_true = next(iter(_finding_stable_keys([f])), None) in all_stable
        else:
            is_true = (f.category, kind) in true_kinds
        if is_true:
            residual_true += 1
        else:
            residual_fp += 1
    return history_residual, residual_true, residual_fp


def _verify_seed(workspace: Workspace, seed: int, mode: str) -> dict[str, Any]:
    fx = workspace.fixture(seed, scripted_fix=True)
    fix = fx.result.fix
    assert fix is not None
    before_findings = workspace.scan(fx)
    fingerprint_before = repo_fingerprint(fx.result.repo)
    work = workspace.root / f"verify-{mode}-{seed}"
    work.mkdir()
    outcome = EXPORT_MODES[mode](workspace, fx, work)
    fingerprint_after = repo_fingerprint(fx.result.repo)

    hits = expected_hits(fx.truth, before_findings, eval_classes=set(EVAL_CLASSES))
    history_hits = [h for h in hits if not (h.kind in _TREE_KINDS and h.at_export_ref)]
    if not outcome.stable_blob_ids:
        # What a kept history carries by design is listed on its own, not scored.
        design_keys = {
            (f.category, key)
            for f in before_findings
            if by_design_reason(f) is not None and (key := finding_key(f)) is not None
        }
        history_hits = [h for h in history_hits if (h.category, h.key) not in design_keys]

    rescan_at: defaultdict[str, set[str]] = defaultdict(set)
    for f in outcome.findings:
        for path in f.location.paths:
            rescan_at[f.category].add(path)
    auto_total = auto_gone = 0
    for h in hits:
        auto_path = fix.auto_resolved.get(h.plant_id)
        if auto_path is None:
            continue
        auto_total += 1
        if auto_path not in rescan_at[h.category]:
            auto_gone += 1

    if outcome.stable_blob_ids:
        rescan_keys = _finding_stable_keys(outcome.findings)
        history_residual = sum(
            1
            for h in history_hits
            if (k := _stable_key(h)) is not None and (k[0], k[1]) in rescan_keys
        )
        all_truth_keys = {k for h in hits if (k := _stable_key(h)) is not None}
        residual_true = residual_fp = 0
        for key in rescan_keys:
            if key in all_truth_keys:
                residual_true += 1
            else:
                residual_fp += 1
        # Findings that carry no stable key (a message, tag or ref finding in the export)
        # cannot match a source truth entry: they are residual false positives.
        residual_fp += sum(
            1
            for f in outcome.findings
            if f.location.kind
            not in ("blob", "unreachable_blob", "binary_field", "path", "identity")
        )
    else:
        history_residual, residual_true, residual_fp = _rewrite_residuals(
            before_findings, hits, history_hits, outcome.findings
        )
    return {
        "seed": seed,
        "source_findings": len(before_findings),
        "refused": outcome.refused,
        "blocking_before_export": outcome.blocking,
        "blocking_kinds": sorted(set(outcome.notes)),
        "clean": outcome.clean,
        "history_only_total": len(history_hits),
        "history_only_eliminated": len(history_hits) - history_residual,
        "head_auto_total": auto_total,
        "head_auto_eliminated": auto_gone,
        "neutralised_plants": len(fix.neutralised),
        "residual_true": residual_true,
        "residual_false_positives": residual_fp,
        "residual_rules": sorted({f"{f.category}/{f.rule_id}" for f in outcome.findings}),
        "left_by_design": sum(outcome.by_design.values()),
        "left_by_design_reasons": dict(sorted(outcome.by_design.items())),
        "immutable": fingerprint_before == fingerprint_after,
    }


def run_export_verify(workspace: Workspace) -> tuple[dict[str, Any], str, bool]:
    options = workspace.options
    modes: dict[str, Any] = {}
    all_ok = True
    for mode in EXPORT_MODES:
        seeds = [_verify_seed(workspace, seed, mode) for seed in options.seeds]
        total = {
            key: sum(s[key] for s in seeds)
            for key in (
                "history_only_total",
                "history_only_eliminated",
                "head_auto_total",
                "head_auto_eliminated",
                "residual_true",
                "residual_false_positives",
                "left_by_design",
            )
        }
        ok = all(s["immutable"] and not s["refused"] for s in seeds) and total["residual_true"] == 0
        all_ok = all_ok and ok
        modes[mode] = {
            "seeds": seeds,
            "total": total,
            "immutable_all": all(s["immutable"] for s in seeds),
            "pass": ok,
        }
    data: dict[str, Any] = {
        "schema": "go-public-bench-export-verify-v1",
        "meta": options.metadata("export-verify", "--export-verify"),
        "modes": modes,
        "pass": all_ok,
    }
    lines = [
        "# Export verification",
        "",
        _meta_block(data["meta"]),
        "",
        "Per seed: scan, scripted fix at HEAD (a final commit that removes every HEAD plant "
        "the export cannot resolve by itself), export, re-scan at `--fail-on low`, and a "
        "fingerprint of the source before and after.",
    ]
    for mode, block in modes.items():
        lines += ["", f"## {mode}", ""]
        rows = [
            [
                s["seed"],
                f"{s['history_only_eliminated']}/{s['history_only_total']}",
                f"{s['head_auto_eliminated']}/{s['head_auto_total']}",
                s["residual_true"],
                s["residual_false_positives"],
                s["left_by_design"] if mode == "keep-history" else "-",
                "yes" if s["immutable"] else "NO",
                "refused" if s["refused"] else ("clean" if s["clean"] else "NOT CLEAN"),
            ]
            for s in block["seeds"]
        ]
        t = block["total"]
        rows.append(
            [
                "all",
                f"{t['history_only_eliminated']}/{t['history_only_total']}",
                f"{t['head_auto_eliminated']}/{t['head_auto_total']}",
                t["residual_true"],
                t["residual_false_positives"],
                t["left_by_design"] if mode == "keep-history" else "-",
                "yes" if block["immutable_all"] else "NO",
                "pass" if block["pass"] else "FAIL",
            ]
        )
        lines.append(
            _table(
                [
                    "Seed",
                    "History-only eliminated",
                    "HEAD auto-resolved eliminated",
                    "Residual true",
                    "Residual false positives",
                    "Left by design",
                    "Source unchanged",
                    "Export",
                ],
                rows,
            )
        )
        if mode == "keep-history":
            reasons: Counter[str] = Counter()
            for seed_block in block["seeds"]:
                reasons.update(seed_block["left_by_design_reasons"])
            listed = ", ".join(f"{r}: {n}" for r, n in sorted(reasons.items())) or "none"
            lines += [
                "",
                "Left by design: licence history (kept as it was, needs a decision), blobs "
                "under the size limit that is dropped, and LFS pointers. They are listed in "
                f"the re-scan report and not scored. This run: {listed}.",
            ]
    return data, "\n".join(lines) + "\n", all_ok


# -- entry point -----------------------------------------------------------------------


@dataclass
class BenchOutcome:
    written: list[Path]
    gates_ok: bool
    summary: list[str]


def run(
    options: BenchOptions,
    *,
    compare_head_only: bool = False,
    export_verify: bool = False,
    blind: bool = False,
) -> BenchOutcome:
    """Run the selected modes (the synthetic table when none is selected) and write
    their results files."""
    if options.size == "medium":
        raise UsageError("bench scores tiny and small fixtures; medium is for --runtime")
    started = time.monotonic()
    written: list[Path] = []
    summary: list[str] = []
    gates_ok = True
    with Workspace(options) as workspace:
        if not (compare_head_only or export_verify or blind):
            data, md, ok = run_synthetic(workspace)
            written += write_results(
                options.out, f"synthetic-{options.label}", data, md, workspace=workspace
            )
            gates_ok = gates_ok and ok
            summary.append(f"synthetic: gates {'pass' if ok else 'FAIL'}")
        if compare_head_only:
            head_data, head_md = run_compare_head_only(workspace)
            written += write_results(
                options.out,
                f"head-only-compare-{options.label}",
                head_data,
                head_md,
                workspace=workspace,
            )
            o = head_data["overall"]
            summary.append(
                f"head-only compare: full {o['full_recall']:.3f}, "
                f"head-only {o['head_only_recall']:.3f}"
            )
        if export_verify:
            verify_data, verify_md, ok = run_export_verify(workspace)
            written += write_results(
                options.out,
                f"export-verify-{options.label}",
                verify_data,
                verify_md,
                workspace=workspace,
            )
            gates_ok = gates_ok and ok
            summary.append(f"export-verify: {'pass' if ok else 'FAIL'}")
        if blind:
            blind_data, blind_md = run_blind_spots(workspace)
            written += write_results(
                options.out,
                f"blind-spots-{options.label}",
                blind_data,
                blind_md,
                workspace=workspace,
            )
            o = blind_data["overall"]
            summary.append(f"blind spots: {o['detected']}/{o['plants']} detected")
    summary.append(f"done in {time.monotonic() - started:.0f}s")
    return BenchOutcome(written=written, gates_ok=gates_ok, summary=summary)
