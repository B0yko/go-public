"""Build synthetic fixture repositories through `git fast-import`.

See architecture.md "Fixture & truth" and `_work/go-public/specs/fixture-api.md` for
the design; this module wires `bench/filler.py` and `bench/plants` together into the
concrete `tiny` fixture. `small`/`medium` and `--blind-spots` are later stages' work.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path

import tomlkit

from go_public.bench import filler
from go_public.bench.plants import LOCATION_TYPES, FixtureContext, Identity, Plant, ResolvedPlant
from go_public.bench.truth import write_truth
from go_public.errors import UsageError
from go_public.git.runner import GitRunner

#: Fictional identities only: reserved-for-documentation domains, per conventions.md.
PUBLIC_IDENTITY: Identity = ("Pat Public", "pat@example.com")
COLLEAGUE_IDENTITIES: tuple[Identity, ...] = (
    ("Alex Rivera", "alex@colleague.example"),
    ("Sam Chen", "sam@colleague.example"),
    ("Jordan Blake", "jordan@colleague.example"),
)

_SIZES = {"tiny"}
_EPOCH = 1_700_000_000  # 2023-11-14T22:13:20Z; a fixed, seed-independent base


@dataclass
class FixtureResult:
    repo: Path
    truth_path: Path
    config_path: Path
    markers: list[ResolvedPlant]


def build(
    seed: int,
    size: str,
    *,
    plants: bool = True,
    blind_spots: bool = False,
    markers_in_truth: bool = False,
    out: Path,
) -> FixtureResult:
    """Build one fixture repository at `out/repo`, plus `truth.jsonl` and config.

    Only `size="tiny"` is implemented so far; `small`, `medium` and `--blind-spots`
    are later stages'. `plants=False` (`--no-plants`) skips the marker plants,
    leaving only filler and topology under the public identity.
    """
    if size not in _SIZES or blind_spots:
        raise UsageError(f"fixture size={size!r} blind_spots={blind_spots} is not implemented yet")
    rng = random.Random(seed)
    ctx = FixtureContext(public_identity=PUBLIC_IDENTITY, base_when=_EPOCH + seed * 100_000)

    _build_topology(ctx, rng)
    if plants:
        _place_markers(ctx, seed)

    out.mkdir(parents=True, exist_ok=True)
    repo = out / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    runner = GitRunner(repo, role="fixture")
    # Bare: fast-import never touches a working tree or index anyway, and a bare
    # repo keeps `scan`'s "uncommitted changes" check (which only applies to a
    # checkout) from firing on a fixture that was never meant to have one.
    runner.run(["init", "-q", "--bare", "--initial-branch=main"])
    runner.run(["config", "user.name", PUBLIC_IDENTITY[0]])
    runner.run(["config", "user.email", PUBLIC_IDENTITY[1]])

    marks_file = out / ".fast-import-marks"
    runner.run(
        ["fast-import", f"--export-marks={marks_file}"],
        input=ctx.render_stream(),
    )
    mark_to_oid = _read_marks(marks_file)
    marks_file.unlink(missing_ok=True)

    resolved = ctx.finalize(runner, mark_to_oid)

    truth_path = out / "truth.jsonl"
    truth_entries = [
        r.truth_entry() for r in resolved if markers_in_truth or r.plant.category != "marker"
    ]
    write_truth(truth_path, truth_entries)

    config_path = out / "go-public.toml"
    config_path.write_text(_fixture_config())

    return FixtureResult(
        repo=repo, truth_path=truth_path, config_path=config_path, markers=resolved
    )


def _build_topology(ctx: FixtureContext, rng: random.Random) -> None:
    """Filler history on main, a merged feature branch, an unmerged side branch."""
    for path, content in filler.generate(rng):
        blob_mark = ctx.blob(content)
        ctx.commit(
            "refs/heads/main",
            message=f"feat: add {path}",
            files={path: blob_mark},
        )

    main_tip = ctx.branch_tip["refs/heads/main"]
    feature_content = filler.python_module(rng, "feature.py")
    feature_blob = ctx.blob(feature_content)
    feature_tip = ctx.commit(
        "refs/heads/feature/enhancement",
        message="feat: add enhancement",
        files={"src/feature.py": feature_blob},
        author=COLLEAGUE_IDENTITIES[0],
        from_=main_tip,
    )
    ctx.commit(
        "refs/heads/main",
        message="merge: enhancement",
        files={"src/feature.py": feature_blob},
        merges=(feature_tip,),
    )

    side_content = filler.markdown_notes(rng, "experiment")
    side_blob = ctx.blob(side_content)
    ctx.commit(
        "refs/heads/side/experiment",
        message="wip: experiment",
        files={"experiment.md": side_blob},
        author=COLLEAGUE_IDENTITIES[1],
        from_=ctx.branch_tip["refs/heads/main"],
    )

    ctx.request_tag(
        "v0.1.0-lw", ctx.branch_tip["refs/heads/main"], message=None, author=ctx.public_identity
    )


def _place_markers(ctx: FixtureContext, seed: int) -> None:
    """One neutral marker per location type, so the inventory can be exercised
    everywhere without a real detector existing yet (Stage 1 brief, 1b)."""
    for location_type in LOCATION_TYPES:
        token = f"marker-{location_type}-{seed:04d}"
        plant = Plant(
            plant_id=f"marker-{location_type}",
            category="marker",
            location_type=location_type,
            content=token.encode(),
            message=f"chore: marker commit ({token})",
            field_name="marker",
        )
        if location_type == "ref_name":
            plant.ref_name = f"refs/heads/markers/{token}"
        ctx.place(plant)


def _read_marks(path: Path) -> dict[str, str]:
    marks: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        mark, oid = line.split()
        marks[mark] = oid
    return marks


def _fixture_config() -> str:
    """A minimal, forward-compatible `go-public.toml` for the fixture (config.py,
    the pydantic schema this will validate against, lands in a later stage)."""
    doc: dict[str, object] = {
        "identity": {"allow": [f"{PUBLIC_IDENTITY[0]} <{PUBLIC_IDENTITY[1]}>"]},
        "deny": {"terms": []},
        "files": {"warn_mb": 1, "high_mb": 5},
        "export": {"author": f"{PUBLIC_IDENTITY[0]} <{PUBLIC_IDENTITY[1]}>"},
    }
    return tomlkit.dumps(doc)
