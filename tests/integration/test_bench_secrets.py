"""Integration gate: the tiny/small fixture's plants, scanned end to end, give
recall = precision = 1.0 for every implemented class; `--no-plants` scans to zero
findings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from go_public import scan
from go_public.bench import fixture
from go_public.bench.match import match
from go_public.bench.truth import read_truth
from go_public.config import load_config
from go_public.git.inventory import build
from go_public.git.runner import GitRunner
from go_public.scan import ScanOptions

_SECRET_CLASSES = {"secret-vendor", "secret-generic"}

#: Every eval_class go-public implements a detector for.
_ALL_IMPLEMENTED_CLASSES = _SECRET_CLASSES | {
    "pii-email",
    "pii-phone",
    "pii-name",
    "org-identifier",
    "local-path",
    "network",
    "sensitive-file",
    "internal-notes",
    "identity",
    "trailer",
    "licence",
    "binary-metadata",
    "large-file",
}


@pytest.mark.parametrize("seed", [0, 1])
@pytest.mark.parametrize("size", ["tiny", "small"])
def test_secret_recall_and_precision_are_perfect_on_fixture(
    tmp_path: Path, seed: int, size: str
) -> None:
    out = tmp_path / f"fixture-{size}-{seed}"
    result = fixture.build(seed, size, out=out)
    truth = read_truth(result.truth_path)

    runner = GitRunner(result.repo, role="source")
    inventory = build(runner, include_unreachable=True)
    findings = scan.run(runner, inventory)

    report = match(truth, findings, eval_classes=_SECRET_CLASSES)
    for eval_class in _SECRET_CLASSES:
        assert report.recall(eval_class) == 1.0, (eval_class, report.unmatched_expected)
        assert report.precision(eval_class) == 1.0, (eval_class, report.unmatched_findings)


@pytest.mark.parametrize("seed", [0, 1])
def test_no_plants_fixture_scans_to_zero_secret_findings(tmp_path: Path, seed: int) -> None:
    out = tmp_path / f"fixture-no-plants-{seed}"
    result = fixture.build(seed, "tiny", plants=False, out=out)
    assert read_truth(result.truth_path) == []

    runner = GitRunner(result.repo, role="source")
    inventory = build(runner, include_unreachable=True)
    findings = scan.run(runner, inventory)

    assert [f for f in findings if f.category == "secret"] == []


def test_only_include_unreachable_finds_the_unreachable_secret_plant(tmp_path: Path) -> None:
    out = tmp_path / "fixture"
    result = fixture.build(0, "tiny", out=out)
    runner = GitRunner(result.repo, role="source")

    default_inventory = build(runner)
    default_findings = scan.run(runner, default_inventory)
    assert not any(f.location.kind == "unreachable_blob" for f in default_findings)

    full_inventory = build(runner, include_unreachable=True)
    full_findings = scan.run(runner, full_inventory)
    assert any(f.location.kind == "unreachable_blob" for f in full_findings)


@pytest.mark.parametrize("seed", [0, 1])
@pytest.mark.parametrize("size", ["tiny", "small"])
def test_recall_and_precision_are_perfect_for_every_implemented_class(
    tmp_path: Path, seed: int, size: str
) -> None:
    out = tmp_path / f"fixture-{size}-{seed}"
    result = fixture.build(seed, size, out=out)
    truth = read_truth(result.truth_path)
    config = load_config(result.config_path)

    runner = GitRunner(result.repo, role="source")
    inventory = build(runner, include_unreachable=True)
    findings = scan.run(runner, inventory, ScanOptions(config=config))

    report = match(truth, findings, eval_classes=_ALL_IMPLEMENTED_CLASSES)
    for eval_class in _ALL_IMPLEMENTED_CLASSES:
        assert report.recall(eval_class) == 1.0, (eval_class, report.unmatched_expected)
        assert report.precision(eval_class) == 1.0, (
            eval_class,
            [(f.rule_id, f.category, f.location) for f in report.unmatched_findings],
        )


@pytest.mark.parametrize(
    ("size", "seed"), [("tiny", 0), ("tiny", 1), ("tiny", 2), ("tiny", 3), ("small", 0)]
)
def test_no_plants_fixture_with_its_own_config_scans_to_zero_findings(
    tmp_path: Path, size: str, seed: int
) -> None:
    """`--no-plants` generates the same filler and hard negatives with only the
    public identity, and scans to zero findings for every seed.
    """
    out = tmp_path / f"fixture-no-plants-{size}-{seed}"
    result = fixture.build(seed, size, plants=False, out=out)
    assert read_truth(result.truth_path) == []
    config = load_config(result.config_path)

    runner = GitRunner(result.repo, role="source")
    inventory = build(runner, include_unreachable=True)
    findings = scan.run(runner, inventory, ScanOptions(config=config))

    assert findings == []
