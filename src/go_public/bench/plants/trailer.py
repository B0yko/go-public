"""Trailer plants: flagged commit trailers (product spec item 10; stage-3.md).

Trailer values use reserved-domain emails (conventions.md: no personal data
committed) unless the plant declares its pii finding as secondary — none here do,
since a trailer's value is checked by `detect/commit_meta.py` alone (stage-3.md's
deny.py bullet does not list trailers among its own scan surfaces).
"""

from __future__ import annotations

import random

from go_public.bench.plants import FixtureContext, Plant

_COUNTS: dict[str, int] = {"tiny": 2, "small": 6}

#: (trailer key, value) pairs; `Change-Id`-style values have no name/email (low
#: severity), the rest do (medium) — architecture.md "Default severities".
_TRAILERS = (
    ("Co-authored-by", "Pat Public <pat@example.com>"),
    ("Reviewed-by", "Pat Public <pat@example.com>"),
    ("Signed-off-by", "Pat Public <pat@example.com>"),
    ("Change-Id", "I0123456789abcdef0123456789abcdef012345"),
    ("Reported-by", "Pat Public <pat@example.com>"),
    ("Acked-by", "Pat Public <pat@example.com>"),
)


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """Build every trailer plant for `size`. `rng`/`ctx` are accepted for signature
    parity (fixture-api.md); unused here (every trailer here is fixed)."""
    del rng, ctx
    total = _COUNTS[size]
    plants = []
    for index in range(total):
        key, value = _TRAILERS[index % len(_TRAILERS)]
        message = f"chore: change {index}\n\n{key}: {value}\n"
        plants.append(
            Plant(
                plant_id=f"trailer-{index:02d}",
                category="trailer",
                location_type="trailer",
                message=message,
                field_name=key,
                eval_class="trailer",
                rule_family="trailer",
            )
        )
    return plants
