"""Network plants: private IPs, internal hostnames and a `.gitmodules` URL to a
private host (product spec item 5; stage-3.md).
"""

from __future__ import annotations

import random

from go_public.bench.plants import FixtureContext, LocationType, Plant, blob_id
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

_COUNTS: dict[str, int] = {"tiny": 3, "small": 8}

_INTERNAL_HOSTS = ("***REMOVED***", "***REMOVED***", "***REMOVED***", "***REMOVED***")


def _private_ip(rng: random.Random) -> str:
    octets = (10, rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254))
    return ".".join(str(o) for o in octets)


def _ip_plant(index: int, location_type: LocationType, rng: random.Random) -> Plant:
    content = f'server_ip = "{_private_ip(rng)}"\n'.encode()
    return Plant(
        plant_id=f"network-ip-{index:02d}",
        category="network",
        location_type=location_type,
        content=content,
        eval_class="network",
        rule_family="private-ip",
    )


def _host_plant(index: int, location_type: LocationType, rng: random.Random) -> Plant:
    host = rng.choice(_INTERNAL_HOSTS)
    content = f'endpoint = "https://{host}/api"\n'.encode()
    return Plant(
        plant_id=f"network-host-{index:02d}",
        category="network",
        location_type=location_type,
        content=content,
        eval_class="network",
        rule_family="internal-host",
    )


def _gitmodules_plant(index: int) -> Plant:
    """A `.gitmodules` file whose submodule URL points at a private host: the only
    plant whose path must literally be `.gitmodules`, so `path_name` carries it (the
    finding itself is still content-based — `blob`/{blob, line} — since
    `detect/paths_network.py` scans the file's *content*, not its path)."""
    content = b'[submodule "vendor"]\n\tpath = vendor\n\turl = https://***REMOVED***/vendor.git\n'
    blob = blob_id(content)
    return Plant(
        plant_id=f"network-gitmodules-{index:02d}",
        category="network",
        location_type="path_name",
        path=".gitmodules",
        content=content,
        eval_class="network",
        rule_family="private-submodule-url",
        suppress_primary_expected=True,
        expected_extra=[
            ExpectedFinding(
                category="network", eval_class="network", kind="blob", key={"blob": blob, "line": 3}
            )
        ],
    )


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """Build every network plant for `size`. `ctx` is accepted for signature parity
    (fixture-api.md); unused here."""
    del ctx
    total = _COUNTS[size]
    plants: list[Plant] = [_gitmodules_plant(0)]
    index = 1
    while len(plants) < total:
        location_type = _CONTENT_LOCATIONS[index % len(_CONTENT_LOCATIONS)]
        if index % 2 == 0:
            plants.append(_ip_plant(index, location_type, rng))
        else:
            plants.append(_host_plant(index, location_type, rng))
        index += 1
    return plants
