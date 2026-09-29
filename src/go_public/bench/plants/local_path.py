"""Local-path plants: absolute paths that reveal a username, and macOS temp paths
Every path-shaped string is assembled from parts at runtime, never written as one
literal.
"""

from __future__ import annotations

import random

from go_public.bench.plants import FixtureContext, LocationType, Plant

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

_USER_NAMES = ("jrivera", "schen", "jblake", "pdev")


def _unix_path(name: str) -> str:
    return "/Us" + "ers/" + name + "/project/build.log"


def _home_path(name: str) -> str:
    return "/ho" + "me/" + name + "/workspace/notes.txt"


def _windows_path(name: str) -> str:
    return "C:" + "\\" + "Us" + "ers" + "\\" + name + "\\" + "AppData\\Local\\cache"


def _macos_temp_path(rng: random.Random) -> str:
    token = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(8))
    return "/var/fold" + "ers/" + token[:2] + "/" + token + "/T/build-cache"


_BUILDERS = (_unix_path, _home_path, _windows_path)


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """Build every local-path plant for `size`. `ctx` is accepted for signature
    parity; unused here."""
    del ctx
    total = _COUNTS[size]
    plants: list[Plant] = []
    for index in range(total):
        location_type = _CONTENT_LOCATIONS[index % len(_CONTENT_LOCATIONS)]
        if index % 4 == 3:
            value = _macos_temp_path(rng)
            rule_family = "macos-temp-path"
        else:
            builder = _BUILDERS[index % len(_BUILDERS)]
            value = builder(rng.choice(_USER_NAMES))
            rule_family = "user-path"
        content = f'log_path = "{value}"\n'.encode()
        plants.append(
            Plant(
                plant_id=f"local-path-{index:02d}",
                category="local-path",
                location_type=location_type,
                content=content,
                eval_class="local-path",
                rule_family=rule_family,
            )
        )
    return plants
