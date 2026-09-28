"""Sensitive-file plants, matched by name (product spec item 9; stage-3.md). Every
plant places content at a path via `path_name`, so the primary expected finding is
the mechanical `path`/`{path}` `detect/files.py` itself produces. One `.env` plant
also embeds a real secret, producing the sensitive-file-plus-secret pair the Data
section's own example names ("a `.env` plant produces a sensitive-file finding and a
secret finding").
"""

from __future__ import annotations

import random

from go_public.bench.plants import FixtureContext, Plant, blob_id
from go_public.bench.plants.secrets import aws_access_key
from go_public.bench.truth import ExpectedFinding

_COUNTS: dict[str, int] = {"tiny": 2, "small": 6}

#: (path, content-is-secret) pairs cycled to build the plant set; the first entry is
#: always used first so the `.env`-plus-secret case is present even at `tiny`.
_PATH_TEMPLATES = (
    ("config/.env", True),
    ("keys/id_rsa", False),
    ("certs/server.pem", False),
    ("backups/dump.sql", False),
    ("secrets/wallet.p12", False),
    ("data/state.sqlite", False),
)


def _plant(index: int, path: str, *, with_secret: bool, rng: random.Random) -> Plant:
    if with_secret:
        token = aws_access_key(rng)
        content = f'ACCESS_KEY="{token}"\n'.encode()
    else:
        content = b"placeholder content\n"
    expected_extra = []
    if with_secret:
        blob = blob_id(content)
        expected_extra.append(
            ExpectedFinding(
                category="secret",
                eval_class="secret-vendor",
                kind="blob",
                key={"blob": blob, "line": 1},
            )
        )
    if path.endswith((".p12", ".pfx")):
        # The bundled gitleaks config's `pkcs12-file` rule is path-only (any
        # `*.p12`/`*.pfx` file, regardless of content): a genuine secondary finding,
        # not a false positive, on `line: 0` (path-only matches carry no offset).
        blob = blob_id(content)
        expected_extra.append(
            ExpectedFinding(
                category="secret",
                eval_class="secret-vendor",
                kind="blob",
                key={"blob": blob, "line": 0},
            )
        )
    return Plant(
        plant_id=f"sensitive-file-{index:02d}",
        category="sensitive-file",
        location_type="path_name",
        path=path,
        content=content,
        eval_class="sensitive-file",
        rule_family="sensitive-file",
        expected_extra=expected_extra,
    )


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """Build every sensitive-file plant for `size`. `ctx` is accepted for signature
    parity (fixture-api.md); unused here."""
    del ctx
    total = _COUNTS[size]
    plants = []
    for index in range(total):
        path, with_secret = _PATH_TEMPLATES[index % len(_PATH_TEMPLATES)]
        if index >= len(_PATH_TEMPLATES):
            # Beyond one cycle: keep paths unique so a later plant never overwrites
            # an earlier one's file at the same path.
            path = f"round{index // len(_PATH_TEMPLATES)}/{path}"
        plants.append(_plant(index, path, with_secret=with_secret, rng=rng))
    return plants
