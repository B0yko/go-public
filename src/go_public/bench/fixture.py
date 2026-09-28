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

from go_public.bench import filler, history, medium, negatives
from go_public.bench.plants import LOCATION_TYPES, FixtureContext, Identity, Plant, ResolvedPlant
from go_public.bench.plants import binary_metadata as binary_metadata_plants
from go_public.bench.plants import blind_spots as blind_spot_plants
from go_public.bench.plants import identity as identity_plants
from go_public.bench.plants import internal_notes as internal_notes_plants
from go_public.bench.plants import large_file as large_file_plants
from go_public.bench.plants import licence as licence_plants
from go_public.bench.plants import local_path as local_path_plants
from go_public.bench.plants import network as network_plants
from go_public.bench.plants import org_identifier as org_identifier_plants
from go_public.bench.plants import pii as pii_plants
from go_public.bench.plants import secrets as secret_plants
from go_public.bench.plants import sensitive_file as sensitive_file_plants
from go_public.bench.plants import trailer as trailer_plants
from go_public.bench.plants._fictional import (
    DENY_DOMAINS,
    DENY_NAMES,
    DENY_REGEXES,
    DENY_TERMS,
    DENY_TICKET_KEYS,
    LICENCE_OWNER,
)
from go_public.bench.truth import write_truth
from go_public.errors import UsageError
from go_public.git.runner import GitRunner
from go_public.plan import is_strip_resolvable

#: Every category's plant module, in a fixed order so seeds are reproducible
#: regardless of dict/set iteration order. Each gets its own `random.Random` seeded
#: from the fixture seed plus its own name, so adding or removing a module never
#: reshuffles another module's RNG stream.
_PLANT_MODULES = (
    secret_plants,
    pii_plants,
    org_identifier_plants,
    local_path_plants,
    network_plants,
    sensitive_file_plants,
    internal_notes_plants,
    identity_plants,
    trailer_plants,
    binary_metadata_plants,
    licence_plants,
    large_file_plants,
)

#: Fictional identities only: reserved-for-documentation domains, per conventions.md.
PUBLIC_IDENTITY: Identity = ("Pat Public", "pat@example.com")
COLLEAGUE_IDENTITIES: tuple[Identity, ...] = (
    ("Alex Rivera", "alex@colleague.example"),
    ("Sam Chen", "sam@colleague.example"),
    ("Jordan Blake", "jordan@colleague.example"),
)

_SIZES = {"tiny", "small", "medium"}
#: Hard negatives per kind (15 kinds): 30 in `tiny`, 150 in `small` (Data section).
_NEGATIVES_PER_KIND = {"tiny": 2, "small": 10}
_EPOCH = 1_700_000_000  # 2023-11-14T22:13:20Z; a fixed, seed-independent base

#: A baseline top-level licence, present regardless of `plants` (unlike every real
#: plant category). Without this, a fixture with no licence plants (`--no-plants`,
#: or any earlier stage's fixture) would legitimately trip `licence-missing-at-head`
#: (product spec item 7), breaking the Data section's "`--no-plants`... scans to
#: zero findings" contract; a real repository being scanned almost always has one.
#: Deliberately carries no "Copyright ... <holder>" line, so it never feeds
#: `licence-foreign-holder` either — `bench/plants/licence.py`'s own plants are the
#: real coverage for both rule ids.
_BASELINE_LICENSE = (
    b"MIT License\n\n"
    b"Permission is hereby granted, free of charge, to any person obtaining a copy\n"
    b"of this software and associated documentation files, to deal in the Software\n"
    b"without restriction.\n"
)


@dataclass(frozen=True)
class FixPlan:
    """What the scripted fix commit of a `scripted_fix` build did (export-verify).

    `neutralised` maps plant id -> path for every HEAD-resident plant the export
    cannot resolve by itself; the fix commit deletes those paths, so their findings
    become history-only. `auto_resolved` maps plant id -> path for HEAD-resident
    plants that stay: the export drops the file (sensitive files, internal notes) or
    strips the metadata field itself."""

    neutralised: dict[str, str]
    auto_resolved: dict[str, str]


_TREE_KINDS = frozenset({"blob", "path", "binary_field", "licence_transition"})
_AUTO_DROPPED_CATEGORIES = frozenset({"sensitive-file", "internal-notes"})
_PRIMARY_KIND = {
    "head": "blob",
    "path_name": "path",
    "binary_field": "binary_field",
    "licence_transition": "licence_transition",
}


def plan_scripted_fix(plants: list[Plant]) -> FixPlan:
    """Decide, for every plant at the export ref, whether the export resolves it by
    itself (`auto_resolved`) or a fix at HEAD must remove it first (`neutralised`).
    The decision mirrors `export/precheck.py`'s notion of "resolved by the export"."""
    neutralised: dict[str, str] = {}
    auto_resolved: dict[str, str] = {}
    for plant in plants:
        path = FixtureContext.tree_path(plant)
        if plant.category == "marker" or path is None:
            continue
        expected: list[tuple[str, str]] = [(e.category, e.kind) for e in plant.expected_extra]
        if not plant.suppress_primary_expected:
            expected.append((plant.category, _PRIMARY_KIND[plant.location_type]))
        tree_categories = {cat for cat, kind in expected if kind in _TREE_KINDS}
        if not tree_categories:
            continue  # identity/trailer/message findings live in history only
        strippable = plant.category == "binary-metadata" and is_strip_resolvable(
            plant.rule_family or ""
        )
        if tree_categories <= _AUTO_DROPPED_CATEGORIES or (
            tree_categories == {"binary-metadata"} and strippable
        ):
            auto_resolved[plant.plant_id] = path
        else:
            neutralised[plant.plant_id] = path
    return FixPlan(neutralised=neutralised, auto_resolved=auto_resolved)


@dataclass
class FixtureResult:
    repo: Path
    truth_path: Path
    config_path: Path
    markers: list[ResolvedPlant]
    #: `truth.blind.jsonl`, written only for a `--blind-spots` build.
    blind_truth_path: Path | None = None
    #: Set for a `scripted_fix` build (export-verify's deterministic variant).
    fix: FixPlan | None = None


def build(
    seed: int,
    size: str,
    *,
    plants: bool = True,
    blind_spots: bool = False,
    markers_in_truth: bool = False,
    medium_scale: float = 1.0,
    scripted_fix: bool = False,
    out: Path,
) -> FixtureResult:
    """Build one fixture repository at `out/repo`, plus `truth.jsonl` and config.

    `plants=False` (`--no-plants`) skips every plant, leaving filler, hard negatives
    and topology under the public identity. `medium` is runtime-sized (seed 100
    targets the product spec's shape); `medium_scale` shrinks it for tests.
    """
    if size not in _SIZES:
        raise UsageError(f"unknown fixture size {size!r} (expected one of {sorted(_SIZES)})")
    rng = random.Random(seed)
    ctx = FixtureContext(
        public_identity=PUBLIC_IDENTITY,
        base_when=_EPOCH + seed * 100_000,
        colleague_identities=COLLEAGUE_IDENTITIES,
    )

    plant_size = "small" if size == "medium" else size
    if size == "medium":
        _build_medium(ctx, rng, medium_scale)
    else:
        _build_topology(ctx, rng, plants=plants, size=size)
    placed: list[Plant] = []
    if plants:
        _place_markers(ctx, seed)
        for category_plants in _PLANT_MODULES:
            module_rng = random.Random(f"{seed}-{category_plants.__name__}")
            for plant in category_plants.generate(module_rng, ctx, size=plant_size):
                ctx.place(plant)
                placed.append(plant)

    fix: FixPlan | None = None
    if scripted_fix:
        fix = plan_scripted_fix(placed)
        if fix.neutralised:
            # One final commit on main removes what the export cannot resolve, so
            # export-verify needs no `git commit` of its own (deterministic variant).
            ctx.commit(
                "refs/heads/main",
                message="chore: remove flagged files",
                files=dict.fromkeys(sorted(set(fix.neutralised.values())), None),
            )
    if blind_spots:
        blind_rng = random.Random(f"{seed}-blind")
        for plant in blind_spot_plants.generate(blind_rng, ctx, size=plant_size):
            ctx.place(plant)

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
    if fix is not None:
        for entry in resolved:
            if entry.plant.plant_id in fix.neutralised:
                entry.at_export_ref = False

    truth_path = out / "truth.jsonl"
    is_blind = [r.plant.plant_id.startswith(blind_spot_plants.BLIND_PREFIX) for r in resolved]
    truth_entries = [
        r.truth_entry()
        for r, blind in zip(resolved, is_blind, strict=True)
        if not blind and (markers_in_truth or r.plant.category != "marker")
    ]
    write_truth(truth_path, truth_entries)
    blind_truth_path: Path | None = None
    if blind_spots:
        blind_truth_path = out / "truth.blind.jsonl"
        write_truth(
            blind_truth_path,
            [r.truth_entry() for r, blind in zip(resolved, is_blind, strict=True) if blind],
        )

    config_path = out / "go-public.toml"
    config_path.write_text(_fixture_config())

    return FixtureResult(
        repo=repo,
        truth_path=truth_path,
        config_path=config_path,
        markers=resolved,
        blind_truth_path=blind_truth_path,
        fix=fix,
    )


def _build_medium(ctx: FixtureContext, rng: random.Random, scale: float) -> None:
    """A runtime-sized repository (product spec Data section): licence, the hard
    negatives, then `bench/medium.py`'s history. `scale` shrinks it for tests."""
    licence_blob = ctx.blob(_BASELINE_LICENSE)
    ctx.commit("refs/heads/main", message="chore: add licence", files={"LICENSE": licence_blob})
    for path, content in negatives.generate(rng, _NEGATIVES_PER_KIND["small"]):
        ctx.commit("refs/heads/main", message=f"docs: add {path}", files={path: ctx.blob(content)})
    shape = medium.MediumShape() if scale == 1.0 else medium.MediumShape().scaled(scale)
    medium.build_history(ctx, rng, shape)


def _build_topology(ctx: FixtureContext, rng: random.Random, *, plants: bool, size: str) -> None:
    """Filler history on main, a merged feature branch, an unmerged side branch.

    The feature/side branch commits are authored by a colleague identity only when
    `plants` is set; `--no-plants` uses the public identity throughout, so that
    build has no identity for `detect/commit_meta.py` to flag (Data section:
    "`--no-plants`... with only the public identity... scans to zero findings").
    Real identity coverage for the colleague identities is `bench/plants/
    identity.py`'s job, which assigns them deliberately (fixture-api.md's own
    "Known gaps" note).
    """
    for path, content in filler.generate(rng):
        blob_mark = ctx.blob(content)
        ctx.commit(
            "refs/heads/main",
            message=f"feat: add {path}",
            files={path: blob_mark},
        )

    licence_blob = ctx.blob(_BASELINE_LICENSE)
    ctx.commit(
        "refs/heads/main",
        message="chore: add licence",
        files={"LICENSE": licence_blob},
    )

    main_tip = ctx.branch_tip["refs/heads/main"]
    feature_author = COLLEAGUE_IDENTITIES[0] if plants else None
    feature_content = filler.python_module(rng, "feature.py")
    feature_blob = ctx.blob(feature_content)
    feature_tip = ctx.commit(
        "refs/heads/feature/enhancement",
        message="feat: add enhancement",
        files={"src/feature.py": feature_blob},
        author=feature_author,
        from_=main_tip,
    )
    ctx.commit(
        "refs/heads/main",
        message="merge: enhancement",
        files={"src/feature.py": feature_blob},
        merges=(feature_tip,),
    )

    side_author = COLLEAGUE_IDENTITIES[1] if plants else None
    side_content = filler.markdown_notes(rng, "experiment")
    side_blob = ctx.blob(side_content)
    ctx.commit(
        "refs/heads/side/experiment",
        message="wip: experiment",
        files={"experiment.md": side_blob},
        author=side_author,
        from_=ctx.branch_tip["refs/heads/main"],
    )

    ctx.request_tag(
        "v0.1.0-lw", ctx.branch_tip["refs/heads/main"], message=None, author=ctx.public_identity
    )

    for path, content in negatives.generate(rng, _NEGATIVES_PER_KIND[size]):
        ctx.commit(
            "refs/heads/main",
            message=f"docs: add {path}",
            files={path: ctx.blob(content)},
        )
    if size == "small":
        history.small_history(ctx, rng, colleagues=COLLEAGUE_IDENTITIES if plants else ())


#: `original` (`refs/original/refs/heads/main`) is a single fixed ref name: `bench/
#: plants/secrets.py`'s own plants always claim it for real (stage 2b), and git
#: allows only one thing there per fixture build (a second `update-ref` would
#: silently orphan whichever placement lost the race) — see that module's
#: `_SINGLETON_LOCATION` comment. Markers stop covering it once real plants do,
#: exactly as fixture-api.md anticipates ("build fewer markers once real coverage
#: of a location type exists").
_MARKER_LOCATIONS = tuple(t for t in LOCATION_TYPES if t != "original")


def _place_markers(ctx: FixtureContext, seed: int) -> None:
    """One neutral marker per location type not already covered by a real plant
    category, so the inventory can be exercised everywhere a detector doesn't exist
    yet (Stage 1 brief, 1b)."""
    for location_type in _MARKER_LOCATIONS:
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
    """The `go-public.toml` a scan of this fixture needs to match `config.py`'s
    schema (stage 2b): the public identity is allowlisted, and `[deny]` lists
    exactly the fictional terms/domains/regexes/ticket keys/names the org-identifier
    and pii plants target (`bench/plants/_fictional.py`), so the deny-list and name
    detectors have something to match against, the same way a real user's config
    would.
    """
    doc: dict[str, object] = {
        "identity": {"allow": [f"{PUBLIC_IDENTITY[0]} <{PUBLIC_IDENTITY[1]}>"]},
        "deny": {
            "terms": list(DENY_TERMS),
            "domains": list(DENY_DOMAINS),
            "regex": list(DENY_REGEXES),
            "names": list(DENY_NAMES),
            "ticket_keys": list(DENY_TICKET_KEYS),
        },
        "files": {"warn_mb": 1, "high_mb": 5},
        "licence": {"owner": LICENCE_OWNER},
        "export": {"author": f"{PUBLIC_IDENTITY[0]} <{PUBLIC_IDENTITY[1]}>"},
    }
    return tomlkit.dumps(doc)
