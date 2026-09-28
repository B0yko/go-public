"""Internal-notes plants, matched by name (product spec item 9; stage-3.md)."""

from __future__ import annotations

import random

from go_public.bench.plants import FixtureContext, Plant

_COUNTS: dict[str, int] = {"tiny": 2, "small": 4}

_PATHS = ("internal/roadmap.md", "NOTES-launch.md", "scratch/idea.txt", "drafts/plan.draft.md")


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """Build every internal-notes plant for `size`. `rng`/`ctx` are accepted for
    signature parity (fixture-api.md); unused here (every path is fixed)."""
    del rng, ctx
    total = _COUNTS[size]
    plants = []
    for index in range(total):
        path = _PATHS[index % len(_PATHS)]
        if index >= len(_PATHS):
            path = f"round{index // len(_PATHS)}/{path}"
        plants.append(
            Plant(
                plant_id=f"internal-notes-{index:02d}",
                category="internal-notes",
                location_type="path_name",
                path=path,
                content=b"internal planning content\n",
                eval_class="internal-notes",
                rule_family="internal-notes",
            )
        )
    return plants
