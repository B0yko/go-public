"""Fixture sizes beyond `tiny`: small's history and negatives, the scaled medium
shape, and the blind-spot plants."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from go_public import scan
from go_public.bench import fixture
from go_public.bench.medium import MediumShape
from go_public.bench.plants import blind_spots
from go_public.bench.truth import read_truth
from go_public.config import load_config
from go_public.git.inventory import build
from go_public.git.runner import GitRunner
from go_public.scan import ScanOptions


def _refs(repo: Path) -> dict[str, str]:
    runner = GitRunner(repo, role="source")
    lines = runner.run(["for-each-ref", "--format=%(refname) %(objecttype)"]).decode().splitlines()
    return {ln.split()[0]: ln.split()[1] for ln in lines}


def test_small_history_is_multi_branch_with_lightweight_and_annotated_tags(
    tmp_path: Path,
) -> None:
    result = fixture.build(0, "small", plants=False, out=tmp_path / "f")
    refs = _refs(result.repo)
    branches = [r for r in refs if r.startswith("refs/heads/")]
    assert {"refs/heads/main", "refs/heads/feature/parser", "refs/heads/side/spike"} <= set(
        branches
    )
    kinds = {refs[r] for r in refs if r.startswith("refs/tags/")}
    assert kinds == {"commit", "tag"}  # lightweight and annotated
    runner = GitRunner(result.repo, role="source")
    assert int(runner.run(["rev-list", "--all", "--count"])) >= 60
    merges = runner.run(["rev-list", "--all", "--merges", "--count"])
    assert int(merges) >= 3


def test_small_is_deterministic(tmp_path: Path) -> None:
    first = fixture.build(3, "small", out=tmp_path / "a")
    second = fixture.build(3, "small", out=tmp_path / "b")
    a = GitRunner(first.repo, role="source").run(["rev-parse", "--all"])
    b = GitRunner(second.repo, role="source").run(["rev-parse", "--all"])
    assert a == b


def test_medium_shape_scales_and_scans_clean(tmp_path: Path) -> None:
    scale = 0.03
    shape = MediumShape().scaled(scale)
    result = fixture.build(100, "medium", plants=False, medium_scale=scale, out=tmp_path / "m")
    runner = GitRunner(result.repo, role="source")
    inventory = build(runner, include_unreachable=True)
    assert not inventory.unreachable_blobs  # no dangling blob from overwritten paths
    branches = [r for r in _refs(result.repo) if r.startswith("refs/heads/")]
    assert len(branches) == 4
    commits = int(runner.run(["rev-list", "--all", "--count"]))
    assert shape.commits <= commits <= shape.commits + 30
    tags = [r for r in _refs(result.repo) if r.startswith("refs/tags/")]
    assert len(tags) == shape.tags
    findings = scan.run(runner, inventory, ScanOptions(config=load_config(result.config_path)))
    assert findings == []


def test_medium_full_shape_constants() -> None:
    shape = MediumShape()
    assert (shape.commits, shape.unique_blobs, shape.binaries, shape.tags) == (3000, 12000, 40, 30)
    assert shape.blob_bytes == 200_000_000


def test_medium_with_plants_has_truth(tmp_path: Path) -> None:
    result = fixture.build(100, "medium", medium_scale=0.02, out=tmp_path / "m")
    assert len(read_truth(result.truth_path)) > 50


def test_blind_spots_write_a_separate_truth_file(tmp_path: Path) -> None:
    result = fixture.build(0, "tiny", blind_spots=True, out=tmp_path / "f")
    assert result.blind_truth_path is not None
    blind = read_truth(result.blind_truth_path)
    assert [e.eval_class for e in blind] == [f"blind-{k}" for k in blind_spots.KINDS]
    main_ids = {e.plant_id for e in read_truth(result.truth_path)}
    assert not any(pid.startswith(blind_spots.BLIND_PREFIX) for pid in main_ids)
    plain = fixture.build(0, "tiny", out=tmp_path / "g")
    assert plain.blind_truth_path is None
    assert not (tmp_path / "g" / "truth.blind.jsonl").exists()


def test_blind_spot_files_are_at_head(tmp_path: Path) -> None:
    result = fixture.build(0, "tiny", plants=False, blind_spots=True, out=tmp_path / "f")
    runner = GitRunner(result.repo, role="source")
    tree = runner.run(["ls-tree", "-r", "--name-only", "HEAD"]).decode().split()
    for path in (
        "blind/split_secret.py",
        "blind/encoded.yaml",
        "blind/bundle.zip",
        "blind/bundle.min.js",
        "blind/screenshot.png",
        "blind/spaced.md",
        "blind/photo.xmp",
    ):
        assert path in tree
    lines = [ln for ln in (result.blind_truth_path or Path()).read_text().splitlines() if ln]
    assert len(lines) == 7
    assert all(json.loads(ln)["at_export_ref"] for ln in lines)


@pytest.mark.parametrize("seed", [0, 1])
def test_small_hard_negatives_present(tmp_path: Path, seed: int) -> None:
    result = fixture.build(seed, "small", plants=False, out=tmp_path / "f")
    runner = GitRunner(result.repo, role="source")
    tree = runner.run(["ls-tree", "-r", "--name-only", "HEAD"]).decode().split()
    assert "docs/contacts.md" in tree and "vendor/upstream/README.md" in tree


def test_tiny_covers_every_class_and_every_location_type(tmp_path: Path) -> None:
    from go_public.bench.plants import LOCATION_TYPES
    from go_public.bench.run import EVAL_CLASSES

    result = fixture.build(0, "tiny", out=tmp_path / "f")
    truth = read_truth(result.truth_path)
    expected_classes = {x.eval_class for e in truth for x in e.expected}
    assert set(EVAL_CLASSES) <= expected_classes
    assert {m.plant.location_type for m in result.markers} == set(LOCATION_TYPES)
    assert {e.category for e in truth} >= {
        "secret",
        "pii",
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
    }
