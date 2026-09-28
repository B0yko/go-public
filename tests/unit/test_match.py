"""`bench/match.py`: category+key matching, duplicate collapsing, per-class FP/FN."""

from __future__ import annotations

from go_public.bench.match import eval_class_for_finding, match
from go_public.bench.truth import ExpectedFinding, TruthEntry
from go_public.model import Finding, FixAction, Location


def _finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = dict(
        fingerprint="f" * 12,
        group_id="g" * 12,
        category="secret",
        rule_id="aws-access-token",
        severity="critical",
        title="t",
        location=Location(kind="blob", blob="b1", line=1, column=1),
        location_key="b1:1:1",
        fix=FixAction(action="rotate"),
    )
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def _truth(plant_id: str, eval_class: str, kind: str, key: dict[str, object]) -> TruthEntry:
    return TruthEntry(
        plant_id=plant_id,
        category="secret",
        eval_class=eval_class,
        location_type="head",
        at_export_ref=True,
        expected=[ExpectedFinding(category="secret", eval_class=eval_class, kind=kind, key=key)],
    )


def test_eval_class_for_finding_splits_generic_from_vendor() -> None:
    assert eval_class_for_finding(_finding(rule_id="aws-access-token")) == "secret-vendor"
    assert eval_class_for_finding(_finding(rule_id="generic-api-key")) == "secret-generic"
    assert eval_class_for_finding(_finding(rule_id="generic-entropy")) == "secret-generic"


def test_eval_class_for_finding_splits_pii_by_rule_id() -> None:
    assert eval_class_for_finding(_finding(category="pii", rule_id="pii-email")) == "pii-email"
    assert eval_class_for_finding(_finding(category="pii", rule_id="pii-phone")) == "pii-phone"
    assert eval_class_for_finding(_finding(category="pii", rule_id="pii-name")) == "pii-name"


def test_matching_blob_finding_satisfies_expected_entry() -> None:
    truth = [_truth("p1", "secret-vendor", "blob", {"blob": "b1", "line": 1})]
    findings = [_finding()]
    report = match(truth, findings)
    assert report.recall("secret-vendor") == 1.0
    assert report.precision("secret-vendor") == 1.0
    assert report.unmatched_expected == []
    assert report.unmatched_findings == []


def test_duplicate_findings_on_one_entry_count_once() -> None:
    truth = [_truth("p1", "secret-generic", "blob", {"blob": "b1", "line": 1})]
    findings = [
        _finding(rule_id="generic-api-key", category="secret"),
        _finding(rule_id="generic-entropy", category="secret"),
    ]
    report = match(truth, findings)
    result = report.by_class["secret-generic"]
    assert result.expected == 1
    assert result.matched_expected == 1
    assert result.findings == 2
    assert result.matched_findings == 2  # both count as matched, not one FP
    assert report.unmatched_findings == []


def test_missing_finding_is_a_false_negative() -> None:
    truth = [_truth("p1", "secret-vendor", "blob", {"blob": "b1", "line": 1})]
    report = match(truth, [])
    assert report.recall("secret-vendor") == 0.0
    assert report.unmatched_expected == [("p1", "secret-vendor")]


def test_stray_finding_is_a_false_positive_in_its_class() -> None:
    truth: list[TruthEntry] = []
    findings = [_finding(location=Location(kind="blob", blob="stray", line=1))]
    report = match(truth, findings)
    assert report.precision("secret-vendor") == 0.0
    assert len(report.unmatched_findings) == 1


def test_commit_message_and_tag_message_keys() -> None:
    truth = [
        _truth("p-commit", "secret-vendor", "commit_message", {"commit": "c1"}),
        _truth("p-tag", "secret-vendor", "tag_message", {"tag": "t1"}),
    ]
    findings = [
        _finding(location=Location(kind="commit_message", commit="c1", line=1)),
        _finding(location=Location(kind="tag_message", tag="t1", line=1)),
    ]
    report = match(truth, findings)
    assert report.recall("secret-vendor") == 1.0
    assert report.precision("secret-vendor") == 1.0


def test_eval_classes_filter_restricts_both_sides() -> None:
    truth = [
        _truth("p1", "secret-vendor", "blob", {"blob": "b1", "line": 1}),
        _truth("p2", "secret-generic", "blob", {"blob": "b2", "line": 1}),
    ]
    findings = [_finding(location=Location(kind="blob", blob="b1", line=1))]
    report = match(truth, findings, eval_classes={"secret-vendor"})
    assert set(report.by_class) == {"secret-vendor"}


def test_recall_and_precision_default_to_one_for_an_unseen_class() -> None:
    report = match([], [])
    assert report.recall("secret-vendor") == 1.0
    assert report.precision("secret-vendor") == 1.0
