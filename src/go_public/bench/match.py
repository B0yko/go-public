"""Match a fixture's `truth.jsonl` against a scan's findings (architecture.md
"Fixture & truth" > "Match keys").

A finding matches an expected entry when `category` and `key` agree; `rule_id` is
never part of the key (a `generic-api-key` and a `generic-entropy` finding at the
same blob/line both satisfy the same secret expectation). Duplicate findings on one
expected entry count once; a finding whose `(category, key)` matches no expected
entry is a false positive in its own eval class. Every kind `_expected_key`/
`_finding_key` handle is now exercised by a real plant module: `blob`/
`unreachable_blob`/`binary_field`/`commit_message`/`tag_message` since stage 2b,
`path`/`ref_name`/`identity`/`trailer` since stage 3a, and `licence_transition`
(matched by `finding.extra["transition_commit"]`, not by location — two independent
transitions could carry identical before/after text) since stage 3b.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from go_public.bench.truth import TruthEntry
from go_public.model import Finding

#: architecture.md "Default severities" / "Secret classes for bench": a secret
#: finding's eval class depends on its rule id, not on which plant produced it.
_GENERIC_SECRET_RULE_IDS = frozenset({"generic-api-key", "generic-entropy"})

Key = tuple[Any, ...]


def eval_class_for_finding(finding: Finding) -> str:
    """Which truth `eval_class` bucket a finding counts against."""
    if finding.category == "secret":
        return "secret-generic" if finding.rule_id in _GENERIC_SECRET_RULE_IDS else "secret-vendor"
    if finding.category == "pii":
        # `detect/pii.py`'s rule ids (pii-email/pii-phone/pii-name) already spell out
        # the truth eval_class (architecture.md: "PII split into email, phone and
        # name" for the per-category recall/precision table).
        return finding.rule_id
    return finding.category


def _expected_key(kind: str, key: Mapping[str, object]) -> Key:
    if kind == "licence_transition":
        # Mirrors `_finding_key`'s own category=="licence" override: matched by
        # `transition_commit`, not by the location the finding also carries
        # (architecture.md "Match keys").
        return (key["commit"],)
    if kind in ("blob", "unreachable_blob"):
        return (key["blob"], key.get("line"))
    if kind == "binary_field":
        return (key["blob"], key["field"])
    if kind == "commit_message":
        return (key["commit"],)
    if kind == "tag_message":
        return (key["tag"],)
    if kind == "trailer":
        return (key["commit"], str(key.get("key", "")).lower())
    if kind in ("path", "ref_name", "identity"):
        return (next(iter(key.values())),)
    raise AssertionError(f"unhandled match kind: {kind!r}")


def _finding_key(finding: Finding) -> Key | None:
    if finding.category == "licence" and "transition_commit" in finding.extra:
        # architecture.md "Match keys": "licence transition -> (commit) via
        # finding.extra['transition_commit']" — the location itself points at the
        # new content's blob (useful in a report), but two independent transitions to
        # identical text would otherwise collide on that blob/line.
        return (finding.extra["transition_commit"],)
    loc = finding.location
    kind = loc.kind
    if kind in ("blob", "unreachable_blob"):
        return (loc.blob, loc.line)
    if kind == "binary_field":
        return (loc.blob, loc.field)
    if kind == "commit_message":
        return (loc.commit,)
    if kind == "tag_message":
        return (loc.tag,)
    if kind == "trailer":
        return (loc.commit, (loc.field or "").lower())
    if kind == "ref_name":
        return (loc.ref,)
    if kind == "identity":
        return (loc.identity,)
    if kind == "path":
        return (loc.paths[0],) if loc.paths else None
    return None


@dataclass(frozen=True, slots=True)
class ClassResult:
    """Recall/precision for one `eval_class` bucket."""

    expected: int = 0
    matched_expected: int = 0
    findings: int = 0
    matched_findings: int = 0

    @property
    def recall(self) -> float:
        return 1.0 if self.expected == 0 else self.matched_expected / self.expected

    @property
    def precision(self) -> float:
        return 1.0 if self.findings == 0 else self.matched_findings / self.findings


@dataclass(frozen=True, slots=True)
class MatchReport:
    by_class: dict[str, ClassResult] = field(default_factory=dict)
    # (plant_id, eval_class) for each expected entry no finding satisfied.
    unmatched_expected: list[tuple[str, str]] = field(default_factory=list)
    unmatched_findings: list[Finding] = field(default_factory=list)

    def recall(self, eval_class: str) -> float:
        result = self.by_class.get(eval_class)
        return 1.0 if result is None else result.recall

    def precision(self, eval_class: str) -> float:
        result = self.by_class.get(eval_class)
        return 1.0 if result is None else result.precision


def match(
    truth_entries: list[TruthEntry],
    findings: list[Finding],
    *,
    eval_classes: set[str] | None = None,
) -> MatchReport:
    """Compare a fixture's truth against a scan's findings.

    `eval_classes`, when given, restricts both sides to those classes — used to
    evaluate only the categories a detector actually exists for yet (stage-2.md:
    "mark expected entries by category so tests evaluate only implemented
    categories").
    """
    expected_items: list[tuple[str, str, str, Key]] = []  # (plant_id, category, class, key)
    for entry in truth_entries:
        for exp in entry.expected:
            if eval_classes is not None and exp.eval_class not in eval_classes:
                continue
            expected_key = _expected_key(exp.kind, exp.key)
            expected_items.append((entry.plant_id, exp.category, exp.eval_class, expected_key))
    expected_key_set = {(category, key) for _pid, category, _cls, key in expected_items}

    considered: list[tuple[Finding, str, Key]] = []
    for finding in findings:
        cls = eval_class_for_finding(finding)
        if eval_classes is not None and cls not in eval_classes:
            continue
        key = _finding_key(finding)
        if key is not None:
            considered.append((finding, cls, key))
    found_key_set = {(finding.category, key) for finding, _cls, key in considered}

    expected_total: Counter[str] = Counter()
    expected_matched: Counter[str] = Counter()
    unmatched_expected: list[tuple[str, str]] = []
    for plant_id, category, cls, key in expected_items:
        expected_total[cls] += 1
        if (category, key) in found_key_set:
            expected_matched[cls] += 1
        else:
            unmatched_expected.append((plant_id, cls))

    findings_total: Counter[str] = Counter()
    findings_matched: Counter[str] = Counter()
    unmatched_findings: list[Finding] = []
    for finding, cls, key in considered:
        findings_total[cls] += 1
        if (finding.category, key) in expected_key_set:
            findings_matched[cls] += 1
        else:
            unmatched_findings.append(finding)

    classes = set(expected_total) | set(findings_total)
    by_class = {
        cls: ClassResult(
            expected=expected_total.get(cls, 0),
            matched_expected=expected_matched.get(cls, 0),
            findings=findings_total.get(cls, 0),
            matched_findings=findings_matched.get(cls, 0),
        )
        for cls in classes
    }
    return MatchReport(
        by_class=by_class,
        unmatched_expected=unmatched_expected,
        unmatched_findings=unmatched_findings,
    )
