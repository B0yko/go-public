"""The fixture framework: determinism, and every marker attributed correctly.

Stage 1 brief (1b): "inventory integration on the tiny fixture: every ref namespace
listed, every marker blob found and attributed to the expected ref(s), dangling
marker only with `--include-unreachable`".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from go_public.bench import fixture
from go_public.bench.plants import LOCATION_TYPES, ResolvedPlant
from go_public.bench.truth import read_truth
from go_public.errors import UsageError
from go_public.git.inventory import Inventory, build
from go_public.git.runner import GitRunner


def _build(tmp_path: Path, name: str, **kwargs: object) -> fixture.FixtureResult:
    return fixture.build(0, "tiny", out=tmp_path / name, **kwargs)  # type: ignore[arg-type]


def test_determinism(tmp_path: Path) -> None:
    first = fixture.build(7, "tiny", out=tmp_path / "a")
    second = fixture.build(7, "tiny", out=tmp_path / "b")
    runner_a = GitRunner(first.repo, role="source")
    runner_b = GitRunner(second.repo, role="source")
    assert runner_a.run(["rev-parse", "--all"]) == runner_b.run(["rev-parse", "--all"])


def test_every_ref_namespace_is_present(tmp_path: Path) -> None:
    result = _build(tmp_path, "repo")
    inv = build(GitRunner(result.repo, role="source"))
    kinds = {r.kind for r in inv.refs}
    assert kinds == {"branch", "tag", "remote", "notes", "stash", "replace", "original"}


def test_all_location_types_are_planted(tmp_path: Path) -> None:
    result = _build(tmp_path, "repo")
    assert {m.plant.location_type for m in result.markers} == set(LOCATION_TYPES)


def _assert_marker_attributed(marker: ResolvedPlant, inv: Inventory) -> None:
    if marker.kind == "blob":
        assert marker.blob in inv.blob_sizes
        assert inv.present_at_export_ref(marker.blob) == marker.at_export_ref
        assert marker.commit is not None and marker.ref is not None
        assert marker.ref in inv.refs_containing(marker.commit)
    elif marker.kind == "unreachable_blob":
        assert marker.blob not in inv.blob_sizes
        assert marker.blob in inv.unreachable_blobs
    elif marker.kind == "ref_name":
        assert any(r.name == marker.ref for r in inv.refs)
    elif marker.kind == "commit_message":
        assert marker.commit is not None
        assert marker.plant.plant_id in inv.commits[marker.commit].message
    elif marker.kind == "tag_message":
        tag_name = (marker.ref or "").rsplit("/", 1)[-1]
        tag = next(t for t in inv.tags.values() if t.tag == tag_name)
        assert marker.plant.plant_id in tag.message


def test_every_marker_is_found_and_attributed(tmp_path: Path) -> None:
    result = _build(tmp_path, "repo", markers_in_truth=True)
    inv = build(GitRunner(result.repo, role="source"), include_unreachable=True)
    # `result.markers` holds every resolved plant (stage 2b's real secret plants now
    # coexist with the neutral markers); `_assert_marker_attributed`'s
    # commit_message/tag_message checks assume a marker's own plant_id is the
    # planted text, which only markers guarantee.
    markers = [m for m in result.markers if m.plant.category == "marker"]
    # "original" is excluded from markers: bench/plants/secrets.py's own plant
    # covers it for real, and git allows only one thing to claim that fixed ref.
    assert len(markers) == len(LOCATION_TYPES) - 1
    for marker in markers:
        _assert_marker_attributed(marker, inv)


def test_dangling_marker_only_with_include_unreachable(tmp_path: Path) -> None:
    result = _build(tmp_path, "repo")
    dangling = next(m for m in result.markers if m.plant.location_type == "unreachable")
    runner = GitRunner(result.repo, role="source")

    default_inv = build(runner)
    assert dangling.blob not in default_inv.blob_sizes
    assert dangling.blob not in default_inv.unreachable_blobs

    full_inv = build(runner, include_unreachable=True)
    assert dangling.blob in full_inv.unreachable_blobs


def test_no_plants_leaves_no_markers(tmp_path: Path) -> None:
    result = _build(tmp_path, "repo", plants=False)
    assert result.markers == []
    assert read_truth(result.truth_path) == []


def test_markers_are_not_written_to_truth_by_default(tmp_path: Path) -> None:
    result = _build(tmp_path, "repo")
    assert result.markers  # the python API still returns them (the "test helper")
    entries = read_truth(result.truth_path)
    assert entries  # stage 2b's real secret plants are non-marker and do appear
    assert all(e.category != "marker" for e in entries)


def test_markers_flag_writes_them_to_truth(tmp_path: Path) -> None:
    result = _build(tmp_path, "repo", markers_in_truth=True)
    entries = read_truth(result.truth_path)
    assert len(entries) == len(result.markers)
    assert {e.location_type for e in entries} == set(LOCATION_TYPES)


def test_unsupported_size_is_not_implemented_yet(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        fixture.build(0, "medium", out=tmp_path / "repo")


def test_blind_spots_is_not_implemented_yet(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        fixture.build(0, "tiny", blind_spots=True, out=tmp_path / "repo")


def test_annotated_tag_points_at_a_commit_on_no_branch(tmp_path: Path) -> None:
    """Stage 1 topology: "one annotated tag pointing at a commit on no branch"."""
    result = _build(tmp_path, "repo")
    inv = build(GitRunner(result.repo, role="source"))
    tag_only = next(m for m in result.markers if m.plant.location_type == "tag_only")
    assert tag_only.commit is not None
    containing = inv.refs_containing(tag_only.commit)
    assert containing == [tag_only.ref]
