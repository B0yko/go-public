"""`go-public bench --real-world-dir D --labels F`: noise on real public repositories.

Two public repositories, each pinned to a release tag, are cloned at bench time (never
vendored) with the clone-only git runner: `psf/requests` at `v2.34.2` and `pallets/flask`
at `3.1.3`. A clone is a full-history bare clone of that one tag (`--single-branch
--branch <tag>`), so the scanned history is the history up to the release and stays
the same when upstream moves on. The bench then

1. checks the tag exists and records its object id, the commit it points to, the clone
   size (`du`-style, allocated blocks) and the licence text found at the tag;
2. scans the clone with `--include-unreachable` and the default config;
3. reports findings per 1,000 unique blobs by severity, leaving the identity category
   out (in a public repository those are true findings by definition; only their count
   is shown);
4. draws a fixed-seed stratified sample of findings at high or above (by repository
   and severity), writes it with its context to `<dir>/private/` for the author to
   label, and computes precision from the labels file.

Nothing that was matched leaves `<dir>/private/`: the results files hold counts, rule
ids, repository names, tags, SHAs and sizes, and the labels file holds fingerprints,
rule ids, verdicts and one-line reasons. Both are checked against every matched value
before they are written.
"""

from __future__ import annotations

import json
import os
import random
import shutil
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from go_public import __version__, pipeline
from go_public.bench.runtime import RuntimeTarget
from go_public.config import Config
from go_public.errors import GoPublicError
from go_public.git.objects import CatFileBatch
from go_public.git.runner import GitRunner, check_git_version
from go_public.model import Finding
from go_public.scan import ScanOptions

#: Severities the precision sample draws from.
SAMPLE_SEVERITIES = ("critical", "high")
SAMPLE_SIZE = 50
SAMPLE_SEED = 20260929
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
VERDICTS = ("TP", "FP")
#: Shortest matched value that is checked for in results and labels files.
_MIN_LEAK_CHECK = 5


class RealWorldError(GoPublicError):
    exit_code = 1


@dataclass(frozen=True)
class RealWorldRepo:
    name: str
    url: str
    tag: str
    #: The licence the repository is expected to carry (SPDX id), checked from its text.
    licence: str

    @property
    def dir_name(self) -> str:
        return self.name.replace("/", "__") + ".git"


REPOS: tuple[RealWorldRepo, ...] = (
    RealWorldRepo("psf/requests", "https://github.com/psf/requests", "v2.34.2", "Apache-2.0"),
    RealWorldRepo("pallets/flask", "https://github.com/pallets/flask", "3.1.3", "BSD-3-Clause"),
)

_LICENCE_FILES = ("LICENSE", "LICENSE.txt", "LICENSE.rst", "LICENSE.md", "COPYING")


# -- clones ------------------------------------------------------------------------------


def clone_path(root: Path, repo: RealWorldRepo) -> Path:
    return root / "clones" / repo.dir_name


def disk_usage_bytes(path: Path) -> int:
    """Allocated size of a tree, like `du -s` (blocks, not apparent size)."""
    total = 0
    for base, _dirs, files in os.walk(path):
        total += os.lstat(base).st_blocks * 512
        for name in files:
            total += os.lstat(os.path.join(base, name)).st_blocks * 512
    return total


def ensure_clone(
    root: Path, repo: RealWorldRepo, *, log: Callable[[str], None] = lambda _l: None
) -> Path:
    """The clone of `repo` under `root`, cloned first when missing. Only the clone
    runner is used, which allows `clone` over https and nothing that writes to a remote."""
    dest = clone_path(root, repo)
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log(f"cloning {repo.name} at {repo.tag}")
    runner = GitRunner(dest.parent, role="clone")
    try:
        runner.run(
            ["clone", "--bare", "--single-branch", "--branch", repo.tag, repo.url, str(dest)]
        )
    except GoPublicError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest


def detect_licence(text: str) -> str | None:
    """A short SPDX-style label for the licence text, or None when it is not recognised."""
    lowered = " ".join(text.lower().split())
    if "apache license" in lowered and "version 2.0" in lowered:
        return "Apache-2.0"
    if "redistribution and use in source and binary forms" in lowered:
        if "neither the name" in lowered:
            return "BSD-3-Clause"
        return "BSD-2-Clause"
    if "permission is hereby granted, free of charge" in lowered:
        return "MIT"
    return None


def describe_clone(clone: Path, repo: RealWorldRepo) -> dict[str, Any]:
    """Facts about the pinned tag: object id, commit, clone size, licence."""
    runner = GitRunner(clone, role="source")
    ref = f"refs/tags/{repo.tag}"
    tag_object = runner.run(["rev-parse", "--verify", "--quiet", ref], check=False).decode().strip()
    if not tag_object:
        raise RealWorldError(f"{repo.name}: tag {repo.tag} not found in the clone")
    commit = runner.run(["rev-parse", "--verify", f"{ref}^{{commit}}"]).decode().strip()
    tag_type = runner.run(["cat-file", "-t", tag_object]).decode().strip()
    licence_file: str | None = None
    licence: str | None = None
    for name in _LICENCE_FILES:
        proc = runner.run(["cat-file", "blob", f"{commit}:{name}"], check=False)
        if proc:
            licence_file = name
            licence = detect_licence(proc.decode("utf-8", "replace"))
            break
    return {
        "repo": repo.name,
        "url": repo.url,
        "tag": repo.tag,
        "tag_kind": "annotated" if tag_type == "tag" else "lightweight",
        "tag_object": tag_object,
        "tag_commit": commit,
        "clone_size_mb": round(disk_usage_bytes(clone) / 1_000_000, 1),
        "licence_file": licence_file,
        "licence_detected": licence,
        "licence_expected": repo.licence,
        "licence_ok": licence == repo.licence,
    }


def flask_runtime_target(
    root: Path, *, log: Callable[[str], None] = lambda _l: None
) -> RuntimeTarget:
    """The `pallets/flask` clone as a (non-gated) runtime target, with the tag, commit and
    clone size as facts."""
    repo = next(r for r in REPOS if r.name == "pallets/flask")
    clone = ensure_clone(root, repo, log=log)
    facts = describe_clone(clone, repo)
    return RuntimeTarget(
        label=f"{repo.name} at {repo.tag} (real-world clone)",
        repo=clone,
        config=None,
        export=False,
        gated=False,
        facts={
            "tag": facts["tag"],
            "tag_commit": facts["tag_commit"][:12],
            "clone_size_mb": facts["clone_size_mb"],
        },
    )


# -- scanning ----------------------------------------------------------------------------


@dataclass
class RepoScan:
    repo: RealWorldRepo
    facts: dict[str, Any]
    findings: list[Finding]
    inventory: dict[str, int]
    duration_s: float
    #: The clone, kept for reading context lines for the private sample.
    clone: Path
    #: Findings present at the pinned tag's tree.
    at_tag: int = 0


def scan_clone(
    clone: Path, repo: RealWorldRepo, facts: dict[str, Any], *, jobs: int, git_version: str
) -> RepoScan:
    config = Config()
    runner = GitRunner(clone, role="source")
    assessment = pipeline.assess(
        runner,
        repo_path=clone,
        ref=facts["tag_commit"],
        config=config,
        config_source="defaults",
        options=ScanOptions.from_config(config, jobs=jobs),
        git_version=git_version,
        fail_on="high",
        include_unreachable=True,
    )
    inv = assessment.report.inventory
    return RepoScan(
        repo=repo,
        facts=facts,
        findings=assessment.findings,
        inventory={
            "commits": inv.commits,
            "refs": inv.refs,
            "unique_blobs": inv.unique_blobs,
            "total_blob_bytes": inv.total_bytes,
            "unreachable_blobs": inv.unreachable_blobs,
        },
        duration_s=assessment.report.scan.duration_s,
        clone=clone,
        at_tag=sum(1 for f in assessment.findings if f.present_at_export_ref),
    )


def rates(scan: RepoScan) -> dict[str, Any]:
    """Counts and per-1,000-unique-blob rates by severity, identity excluded."""
    blobs = max(scan.inventory["unique_blobs"], 1)
    non_identity = [f for f in scan.findings if f.category != "identity"]
    by_severity = Counter(f.severity for f in non_identity)
    by_category = Counter(f.category for f in non_identity)
    by_rule = Counter(f.rule_id for f in non_identity)
    return {
        "identity_findings": sum(1 for f in scan.findings if f.category == "identity"),
        "findings_excluding_identity": len(non_identity),
        "by_severity": {
            s: {"count": by_severity[s], "per_1000_blobs": round(by_severity[s] * 1000 / blobs, 2)}
            for s in SEVERITY_ORDER
        },
        "by_category": dict(sorted(by_category.items())),
        "by_rule": dict(sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))),
        "per_1000_blobs_all": round(len(non_identity) * 1000 / blobs, 2),
        "present_at_tag": scan.at_tag,
    }


# -- the sample --------------------------------------------------------------------------


def allocate(strata: dict[tuple[str, str], int], size: int) -> dict[tuple[str, str], int]:
    """Proportional allocation of `size` draws over strata (largest remainder), every
    non-empty stratum getting at least one draw while the budget allows; all of a
    stratum when it is smaller than its share. Deterministic."""
    total = sum(strata.values())
    if total <= size:
        return dict(strata)
    keys = sorted(strata)
    quota = {k: size * strata[k] / total for k in keys}
    alloc = {k: int(quota[k]) for k in keys}
    if size >= len(keys):
        for k in keys:
            alloc[k] = max(alloc[k], 1)
    left = size - sum(alloc.values())
    order = sorted(keys, key=lambda k: (-(quota[k] - int(quota[k])), k))
    while left > 0:
        progressed = False
        for k in order:
            if left > 0 and alloc[k] < strata[k]:
                alloc[k] += 1
                left -= 1
                progressed = True
        if not progressed:
            break
    while left < 0:  # the minimum of one overshot: take from the largest strata
        k = max(keys, key=lambda x: (alloc[x], x))
        alloc[k] -= 1
        left += 1
    return {k: min(v, strata[k]) for k, v in alloc.items()}


@dataclass
class SampleItem:
    repo: str
    finding: Finding
    scan: RepoScan = field(repr=False)


def draw_sample(
    scans: Sequence[RepoScan], *, size: int = SAMPLE_SIZE, seed: int = SAMPLE_SEED
) -> list[SampleItem]:
    """Fixed-seed stratified sample of findings at high or above, by repository and
    severity. Findings are ordered by fingerprint before drawing, so the result depends
    on the scan's findings only."""
    pool: dict[tuple[str, str], list[SampleItem]] = {}
    for scan in scans:
        for finding in sorted(scan.findings, key=lambda f: f.fingerprint):
            if finding.severity in SAMPLE_SEVERITIES:
                pool.setdefault((scan.repo.name, finding.severity), []).append(
                    SampleItem(scan.repo.name, finding, scan)
                )
    alloc = allocate({k: len(v) for k, v in pool.items()}, size)
    picked: list[SampleItem] = []
    for key in sorted(pool):
        rng = random.Random(f"{seed}|{key[0]}|{key[1]}")
        picked.extend(rng.sample(pool[key], alloc[key]))
    return sorted(picked, key=lambda i: (i.repo, i.finding.severity, i.finding.fingerprint))


class ContextReader:
    """Source lines of blob findings, read through one `cat-file --batch` per clone and
    remembered for the last few blobs (findings of one blob come in runs)."""

    def __init__(self, clone: Path) -> None:
        self._batch = CatFileBatch(GitRunner(clone, role="source"))
        self._cache: dict[str, list[str]] = {}

    def __enter__(self) -> ContextReader:
        self._batch.__enter__()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._batch.__exit__(*exc_info)

    def context(self, finding: Finding) -> str:
        loc = finding.location
        if loc.kind not in ("blob", "unreachable_blob") or not loc.blob or not loc.line:
            return ""
        if loc.blob not in self._cache:
            got = self._batch.get(loc.blob)
            text = got[1].decode("utf-8", "replace") if got else ""
            self._cache[loc.blob] = text.splitlines()
            if len(self._cache) > 32:
                self._cache.pop(next(iter(self._cache)))
        lines = self._cache[loc.blob]
        if loc.line > len(lines):
            return ""
        text = lines[loc.line - 1]
        col = max((loc.column or 1) - 1, 0)
        start = max(col - 80, 0)
        return text[start : start + 240]


def write_private_sample(root: Path, sample: Sequence[SampleItem]) -> Path:
    """`<root>/private/sample.jsonl`: everything the author needs to label a finding
    (preview and the source line included). Never committed, never copied anywhere."""
    private = root / "private"
    private.mkdir(parents=True, exist_ok=True)
    private.chmod(0o700)
    readers: dict[Path, ContextReader] = {}
    lines = []
    for item in sample:
        f = item.finding
        reader = readers.get(item.scan.clone)
        if reader is None:
            reader = readers[item.scan.clone] = ContextReader(item.scan.clone).__enter__()
        lines.append(
            json.dumps(
                {
                    "repo": item.repo,
                    "fingerprint": f.fingerprint,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "category": f.category,
                    "kind": f.location.kind,
                    "paths": f.location.paths[:3],
                    "line": f.location.line,
                    "present_at_tag": f.present_at_export_ref,
                    "preview": f.preview,
                    "context": reader.context(f),
                    "value": f.raw_value,
                }
            )
        )
    for reader in readers.values():
        reader.__exit__(None, None, None)
    path = private / "sample.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def write_private_findings(root: Path, scans: Sequence[RepoScan]) -> Path:
    """`<root>/private/findings.jsonl`: every finding with its matched value, for hunting
    false-positive patterns. Private like the sample."""
    private = root / "private"
    private.mkdir(parents=True, exist_ok=True)
    private.chmod(0o700)
    rows = []
    for scan in scans:
        with ContextReader(scan.clone) as reader:
            for f in sorted(scan.findings, key=lambda x: (x.location.blob or "", x.fingerprint)):
                rows.append(
                    json.dumps(
                        {
                            "repo": scan.repo.name,
                            "fingerprint": f.fingerprint,
                            "rule_id": f.rule_id,
                            "severity": f.severity,
                            "category": f.category,
                            "kind": f.location.kind,
                            "paths": f.location.paths[:2],
                            "line": f.location.line,
                            "present_at_tag": f.present_at_export_ref,
                            "context": reader.context(f) if f.severity != "info" else "",
                            "value": f.raw_value,
                        }
                    )
                )
    path = private / "findings.jsonl"
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


# -- labels ------------------------------------------------------------------------------


def read_labels(path: Path) -> dict[str, dict[str, str]]:
    """The labels file: one JSON object per line with `fingerprint`, `rule_id`,
    `verdict` (TP or FP) and a one-line `reason`."""
    labels: dict[str, dict[str, str]] = {}
    if not path.exists():
        return labels
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RealWorldError(f"{path.name}:{number}: not JSON ({exc.msg})") from exc
        if not isinstance(entry, dict):
            raise RealWorldError(f"{path.name}:{number}: not a JSON object")
        missing = {"fingerprint", "rule_id", "verdict", "reason"} - set(entry)
        if missing:
            raise RealWorldError(f"{path.name}:{number}: missing {sorted(missing)}")
        if entry["verdict"] not in VERDICTS:
            raise RealWorldError(f"{path.name}:{number}: verdict must be TP or FP")
        reason = str(entry["reason"]).strip()
        if not reason or "\n" in reason:
            raise RealWorldError(f"{path.name}:{number}: reason must be one non-empty line")
        if entry["fingerprint"] in labels:
            raise RealWorldError(f"{path.name}:{number}: duplicate fingerprint")
        labels[entry["fingerprint"]] = {k: str(v) for k, v in entry.items()}
    return labels


def precision(sample: Sequence[SampleItem], labels: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Precision on the labelled part of the sample, overall and by repository, severity
    and rule."""
    total: Counter[str] = Counter()
    tp: Counter[str] = Counter()
    pending = 0
    fp_rules: Counter[str] = Counter()
    by_rule: dict[str, list[int]] = {}
    for item in sample:
        label = labels.get(item.finding.fingerprint)
        if label is None:
            pending += 1
            continue
        keys = ("all", f"repo:{item.repo}", f"severity:{item.finding.severity}")
        for key in keys:
            total[key] += 1
            tp[key] += label["verdict"] == "TP"
        counts = by_rule.setdefault(item.finding.rule_id, [0, 0])
        counts[0] += 1
        counts[1] += label["verdict"] == "TP"
        if label["verdict"] == "FP":
            fp_rules[item.finding.rule_id] += 1

    def entry(key: str) -> dict[str, Any]:
        n = total[key]
        return {
            "labelled": n,
            "tp": tp[key],
            "fp": n - tp[key],
            "precision": round(tp[key] / n, 3) if n else None,
        }

    return {
        "sampled": len(sample),
        "labelled": total["all"],
        "pending": pending,
        "overall": entry("all"),
        "by_repo": {
            k.removeprefix("repo:"): entry(k) for k in sorted(total) if k.startswith("repo:")
        },
        "by_severity": {
            k.removeprefix("severity:"): entry(k)
            for k in sorted(total)
            if k.startswith("severity:")
        },
        "by_rule": {
            rule: {"labelled": n, "tp": t, "fp": n - t, "precision": round(t / n, 3)}
            for rule, (n, t) in sorted(by_rule.items())
        },
    }


def stale_labels(sample: Sequence[SampleItem], labels: dict[str, dict[str, str]]) -> list[str]:
    """Label fingerprints that are not in the current sample (a sign that the sample
    or the detectors changed since labelling)."""
    current = {i.finding.fingerprint for i in sample}
    return sorted(set(labels) - current)


# -- leak check ----------------------------------------------------------------------------


#: Findings whose values are checked for: medium or above, and not licence text (whose
#: values, such as a licence name, are ordinary results-file vocabulary). Low and info
#: findings are software names, timestamps and archive kinds.
_LEAK_CHECKED_SEVERITIES = frozenset({"critical", "high", "medium"})


def matched_values(scans: Iterable[RepoScan]) -> dict[str, set[str]]:
    """Every matched value of the scans long enough to check for, with the rule ids that
    matched it."""
    values: dict[str, set[str]] = {}
    for scan in scans:
        for finding in scan.findings:
            if finding.severity not in _LEAK_CHECKED_SEVERITIES or finding.category == "licence":
                continue
            value = finding.raw_value
            if value and len(value) >= _MIN_LEAK_CHECK:
                values.setdefault(value, set()).add(finding.rule_id)
    return values


def assert_no_values(text: str, values: dict[str, set[str]], what: str) -> None:
    """Raise when `text` contains any matched value (the message names rule ids, never
    the value)."""
    hits = sorted({rule for value, rules in values.items() if value in text for rule in rules})
    if hits:
        raise RealWorldError(
            f"refusing to write {what}: it contains matched values of rules {', '.join(hits)}"
        )


# -- results -----------------------------------------------------------------------------


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return "\n".join(lines)


def build_results(
    scans: Sequence[RepoScan],
    sample: Sequence[SampleItem],
    labels: dict[str, dict[str, str]],
    *,
    hardware: str,
    detector_commit: str,
    labels_name: str,
) -> tuple[dict[str, Any], str]:
    meta = {
        "mode": "real-world",
        "date_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hardware": hardware,
        "git_version": check_git_version().removeprefix("git version "),
        "go_public_version": __version__,
        "detector_commit": detector_commit,
        "command": f"go-public bench --real-world-dir <dir> --labels {labels_name}",
    }
    repos = []
    for scan in scans:
        repos.append(
            {
                **scan.facts,
                "inventory": scan.inventory,
                "scan_duration_s": scan.duration_s,
                "noise": rates(scan),
            }
        )
    prec = precision(sample, labels)
    strata = Counter((i.repo, i.finding.severity) for i in sample)
    pool = Counter(
        (s.repo.name, f.severity)
        for s in scans
        for f in s.findings
        if f.severity in SAMPLE_SEVERITIES
    )
    data: dict[str, Any] = {
        "schema": "go-public-bench-real-world-v1",
        "meta": meta,
        "repos": repos,
        "sample": {
            "size": SAMPLE_SIZE,
            "seed": SAMPLE_SEED,
            "severities": list(SAMPLE_SEVERITIES),
            "strata": [
                {"repo": r, "severity": s, "population": pool[(r, s)], "drawn": strata[(r, s)]}
                for r, s in sorted(pool)
            ],
            "rules": dict(sorted(Counter(i.finding.rule_id for i in sample).items())),
        },
        "precision": prec,
    }
    return data, _markdown(data)


def _markdown(data: dict[str, Any]) -> str:
    meta = data["meta"]
    out = [
        "# Real-world noise",
        "",
        f"- Date (UTC): {meta['date_utc']}",
        f"- Hardware: {meta['hardware']}",
        f"- git: {meta['git_version']}",
        f"- go-public: {meta['go_public_version']}",
        f"- Detector commit: {meta['detector_commit']}",
        f"- Command: `{meta['command']}`",
        "",
        "Two public repositories, each a full-history clone of one release tag, scanned "
        "with `--include-unreachable` and the default configuration. The results hold "
        "counts, rule ids, tags, SHAs and sizes only; no matched value from either "
        "repository is written anywhere in this repository.",
        "",
        "## Repositories",
        "",
    ]
    rows = []
    for r in data["repos"]:
        inv = r["inventory"]
        rows.append(
            [
                r["repo"],
                r["tag"],
                f"`{r['tag_commit'][:12]}`",
                f"{r['clone_size_mb']} MB",
                f"{r['licence_detected'] or 'unrecognised'}",
                f"{inv['commits']:,}",
                f"{inv['unique_blobs']:,}",
                f"{inv['total_blob_bytes'] / 1_000_000:.0f} MB",
                f"{r['scan_duration_s']:.1f} s",
            ]
        )
    out.append(
        _table(
            [
                "Repository",
                "Tag",
                "Tag commit",
                "Clone size",
                "Licence",
                "Commits",
                "Unique blobs",
                "Blob content",
                "Scan",
            ],
            rows,
        )
    )
    out += ["", "## Findings per 1,000 unique blobs", ""]
    out.append(
        "Identity findings are left out (in a public repository they are true findings by "
        "definition); their count is shown in the last column."
    )
    out.append("")
    rows = []
    for r in data["repos"]:
        n = r["noise"]
        row = [r["repo"]]
        for sev in SEVERITY_ORDER:
            s = n["by_severity"][sev]
            row.append(f"{s['count']} ({s['per_1000_blobs']:.2f})")
        row += [
            f"{n['findings_excluding_identity']} ({n['per_1000_blobs_all']:.2f})",
            n["identity_findings"],
        ]
        rows.append(row)
    out.append(
        _table(["Repository", "Critical", "High", "Medium", "Low", "Info", "All", "Identity"], rows)
    )
    out.append("")
    out.append("Cells are count (per 1,000 unique blobs).")
    for r in data["repos"]:
        n = r["noise"]
        out += ["", f"### {r['repo']}: findings by rule (identity excluded)", ""]
        out.append(_table(["Rule", "Findings"], [[k, v] for k, v in n["by_rule"].items()]))
    out += [
        "",
        "## Tuning on these repositories",
        "",
        "The first scans of these two repositories exposed false-positive patterns that the "
        "synthetic hard negatives did not contain (numeric data such as SVG path data and "
        "coefficient tables read as phone numbers, dotted code references read as "
        "internal hosts, placeholder home directories, URL "
        "credentials read as emails, `module.Attribute` values read as credentials, and "
        "permissive licence headers read as proprietary notices). They were fixed before "
        "the detector freeze, each with a test built from runtime-assembled strings. The "
        "numbers on this page are after those fixes, so on these two repositories they "
        "are a measure of what remains, not an independent test of the patterns that "
        "were fixed.",
        "",
        "## Precision on a reviewed sample",
        "",
    ]
    sample = data["sample"]
    out.append(
        f"Up to {sample['size']} findings at {' or '.join(sample['severities'])}, drawn with "
        f"the fixed seed {sample['seed']}: strata are repository and severity, each stratum "
        "gets its proportional share (at least one draw), and findings are ordered by "
        "fingerprint before drawing. The sample is reproduced by re-running the command above "
        "on the same clones; it is labelled by the author (the labels file holds "
        "fingerprints, rule ids, verdicts and one-line reasons, never a matched value). "
        "A finding is a true positive when the flagged value is what the rule claims, "
        "whether or not publishing it is harmful; a path rule (`sensitive-file`) is judged "
        "by its name pattern only. Shares are proportional to each stratum's size, so the "
        "most common rule dominates the sample; the per-rule counts above show what the "
        "sample does not cover."
    )
    out.append("")
    out.append(
        _table(
            ["Repository", "Severity", "Findings at or above high", "Drawn"],
            [[s["repo"], s["severity"], s["population"], s["drawn"]] for s in sample["strata"]],
        )
    )
    prec = data["precision"]
    out.append("")
    if prec["pending"]:
        out.append(
            f"Labels are incomplete: {prec['labelled']} of {prec['sampled']} sampled findings "
            "are labelled."
        )
        out.append("")
    o = prec["overall"]
    out.append(
        f"Overall: {o['tp']} true positives, {o['fp']} false positives among {o['labelled']} "
        f"labelled findings; precision {_pct(o['precision'])}."
    )
    out.append("")
    rows = [
        [f"repository {k}", v["labelled"], v["tp"], v["fp"], _pct(v["precision"])]
        for k, v in prec["by_repo"].items()
    ]
    rows += [
        [f"severity {k}", v["labelled"], v["tp"], v["fp"], _pct(v["precision"])]
        for k, v in prec["by_severity"].items()
    ]
    rows += [
        [f"rule {k}", v["labelled"], v["tp"], v["fp"], _pct(v["precision"])]
        for k, v in prec["by_rule"].items()
    ]
    out.append(_table(["Slice", "Labelled", "TP", "FP", "Precision"], rows))
    out.append("")
    return "\n".join(out)
