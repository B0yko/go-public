"""PII plants: emails, phone numbers and a flagged name.

Email plants use `.internal` domains (ICANN-reserved for private use: detected as
emails, never a real public address) and each also expects the secondary
`network`/`internal-host` finding for the same hostname, on the same line (their
truth entries also list the secondary network finding for the hostname). Phone plants
use NANP 555-0100..0199 and the GB Ofcom drama ranges, verified against `phonenumbers`.
"""

from __future__ import annotations

import random

from go_public.bench.plants import FixtureContext, LocationType, Plant, blob_id
from go_public.bench.plants._fictional import FLAGGED_NAME
from go_public.bench.truth import ExpectedFinding

_CONTENT_LOCATIONS: tuple[LocationType, ...] = (
    "head",
    "history_only",
    "side_branch",
    "tag_only",
    "notes",
    "stash",
    "remote_tracking",
    "unreachable",
)

#: `size` -> (email count, phone count, name count); the small seed
#: has 6 emails, 6 phones and 3 names.
_COUNTS: dict[str, tuple[int, int, int]] = {"tiny": (2, 2, 1), "small": (6, 6, 3)}

_INTERNAL_DOMAIN_WORDS = ("build", "deploy", "release", "staging", "metrics", "infra")
_LOCAL_PARTS = ("jordan", "morgan", "sam", "alex", "devteam", "oncall")

#: NANP 555 numbers reserved for fiction (any 0100-0199 range is documented fictional
#: per the NANPA); verified VALID at `phonenumbers` `Leniency.VALID`.
_NANP_LINES = tuple(f"555-01{n:02d}" for n in range(0, 100))
_NANP_AREA_CODES = ("202", "415", "312", "646")
#: GB Ofcom drama ranges (020 7946 0xxx, 0113 496 0xxx, 0161 496 0xxx); the mobile
#: drama range 07700 900xxx is deliberately NOT used (not VALID).
_GB_NUMBERS = tuple(f"020 7946 0{n:03d}" for n in range(100, 200)) + tuple(
    f"0113 496 0{n:03d}" for n in range(100, 200)
)


def _email_plant(index: int, location_type: LocationType, rng: random.Random) -> Plant:
    local = rng.choice(_LOCAL_PARTS) + str(rng.randint(10, 99))
    domain = rng.choice(_INTERNAL_DOMAIN_WORDS) + ".internal"
    content = f'contact = "{local}@{domain}"\n'.encode()
    blob = blob_id(content)
    # The secondary network finding shares the primary's blob-based kind: "blob" for
    # every content-bearing location here except "unreachable", which the pipeline
    # (scan.py) reports as "unreachable_blob" instead.
    secondary_kind = "unreachable_blob" if location_type == "unreachable" else "blob"
    return Plant(
        plant_id=f"pii-email-{index:02d}",
        category="pii",
        location_type=location_type,
        content=content,
        eval_class="pii-email",
        rule_family="pii-email",
        expected_extra=[
            ExpectedFinding(
                category="network",
                eval_class="network",
                kind=secondary_kind,
                key={"blob": blob, "line": 1},
            )
        ],
    )


def _phone_plant(index: int, location_type: LocationType, rng: random.Random) -> Plant:
    if index % 2 == 0:
        number = f"+1 {rng.choice(_NANP_AREA_CODES)}-{rng.choice(_NANP_LINES)}"
    else:
        number = rng.choice(_GB_NUMBERS)
    content = f'phone = "{number}"\n'.encode()
    return Plant(
        plant_id=f"pii-phone-{index:02d}",
        category="pii",
        location_type=location_type,
        content=content,
        eval_class="pii-phone",
        rule_family="pii-phone",
    )


def _name_plant(index: int, location_type: LocationType) -> Plant:
    content = f'reviewer = "{FLAGGED_NAME}"\n'.encode()
    return Plant(
        plant_id=f"pii-name-{index:02d}",
        category="pii",
        location_type=location_type,
        content=content,
        eval_class="pii-name",
        rule_family="pii-name",
    )


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """Build every pii plant for `size`. `ctx` is accepted for signature parity with
    other plant modules; unused here."""
    del ctx
    email_count, phone_count, name_count = _COUNTS[size]
    plants: list[Plant] = []
    for i in range(email_count):
        plants.append(_email_plant(i, _CONTENT_LOCATIONS[i % len(_CONTENT_LOCATIONS)], rng))
    for i in range(phone_count):
        plants.append(_phone_plant(i, _CONTENT_LOCATIONS[i % len(_CONTENT_LOCATIONS)], rng))
    for i in range(name_count):
        plants.append(_name_plant(i, _CONTENT_LOCATIONS[i % len(_CONTENT_LOCATIONS)]))
    return plants
