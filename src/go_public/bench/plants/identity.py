"""Identity plants: the three colleague identities. Each plant is an ordinary
content-bearing commit authored by one colleague; the mechanical primary expected
finding (`blob`/`{blob, line}`) is suppressed in favour of the real
`identity`/`{identity}` finding `detect/commit_meta.py` produces, since identity
detection works from commit metadata, not blob content.
"""

from __future__ import annotations

import random

from go_public.bench.plants import FixtureContext, LocationType, Plant
from go_public.bench.truth import ExpectedFinding

_LOCATIONS: tuple[LocationType, ...] = ("head", "side_branch", "history_only")

_COUNTS: dict[str, int] = {"tiny": 3, "small": 3}


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """One plant per colleague identity (`ctx.colleague_identities`), each authoring
    an ordinary commit at a different location type. `rng` is accepted for signature
    parity; unused here (identities are fixed, not sampled)."""
    del rng
    total = min(_COUNTS[size], len(ctx.colleague_identities))
    plants = []
    for index in range(total):
        name, email = ctx.colleague_identities[index]
        location_type = _LOCATIONS[index % len(_LOCATIONS)]
        plants.append(
            Plant(
                plant_id=f"identity-{index:02d}",
                category="identity",
                location_type=location_type,
                path=f"work/{name.split()[0].lower()}.txt",
                content=f"notes by {name}\n".encode(),
                author=(name, email),
                message=f"chore: work by {name}",
                eval_class="identity",
                rule_family="identity",
                suppress_primary_expected=True,
                expected_extra=[
                    ExpectedFinding(
                        category="identity",
                        eval_class="identity",
                        kind="identity",
                        key={"identity": f"{name} <{email}>"},
                    )
                ],
            )
        )
    return plants
