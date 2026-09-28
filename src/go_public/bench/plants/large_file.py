"""Large-file / LFS-pointer plants (product spec item 8; stage-3.md 3b): one blob
each for the `large-file-warn` and `large-file-high` tiers (`bench/fixture.py`'s
generated config lowers `warn_mb`/`high_mb` to 1/5 so these stay small), plus one
Git LFS pointer blob.

The real GitHub 100 MB tier (`large-file-github-limit`) is not planted: it is a
fixed, non-configurable threshold (`scan.py`'s own `_GITHUB_LIMIT_BYTES`), and a
literal 100+ MB blob in every fixture build would make `tiny`/`small` far too slow
for CI; `tests/unit/test_scan.py` covers that tier directly instead (STATUS.md).

Every plant's content carries a leading NUL byte so `detect/base.py`'s routing
classifies it as binary and no text detector ever runs over multiple megabytes of
random fill (also sidesteps any chance of an incidental secret/PII look-alike in
high-entropy random bytes). The large-file/gitlink/lfs-pointer findings themselves
come from blob size and content-prefix checks in `scan.py`, not from the routed
content, so this has no effect on detection.
"""

from __future__ import annotations

import random

from go_public.bench.plants import FixtureContext, Plant, blob_id
from go_public.bench.truth import ExpectedFinding

_COUNTS: dict[str, int] = {"tiny": 2, "small": 3}

_ONE_MB = 1024 * 1024
#: `bench/fixture.py`'s `_fixture_config` sets `[files] warn_mb = 1, high_mb = 5`.
_WARN_TIER_SIZE = 1 * _ONE_MB + 4096
_HIGH_TIER_SIZE = 5 * _ONE_MB + 4096

_LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1\n"


def _binary_fill(rng: random.Random, size: int) -> bytes:
    return b"\x00" + rng.randbytes(size - 1)


def _large_blob_plant(plant_id: str, content: bytes) -> Plant:
    blob = blob_id(content)
    return Plant(
        plant_id=plant_id,
        category="large-file",
        location_type="head",
        path=f"markers/{plant_id}.bin",
        content=content,
        eval_class="large-file",
        rule_family="large-file",
        # `_scan_large_files`'s finding has no specific line (the whole blob is the
        # subject, not one match position), so it reports `line: 0`, unlike
        # `_place_head`'s own default primary key (`line: 1`).
        suppress_primary_expected=True,
        expected_extra=[
            ExpectedFinding(
                category="large-file",
                eval_class="large-file",
                kind="blob",
                key={"blob": blob, "line": 0},
            )
        ],
    )


def _lfs_pointer_plant(rng: random.Random, plant_id: str) -> Plant:
    oid = "".join(rng.choice("0123456789abcdef") for _ in range(64))
    content = _LFS_POINTER_PREFIX + f"oid sha256:{oid}\nsize 123456\n".encode()
    blob = blob_id(content)
    return Plant(
        plant_id=plant_id,
        category="large-file",
        location_type="head",
        path=f"markers/{plant_id}.bin",
        content=content,
        eval_class="large-file",
        rule_family="lfs-pointer",
        suppress_primary_expected=True,
        expected_extra=[
            ExpectedFinding(
                category="large-file",
                eval_class="large-file",
                kind="blob",
                key={"blob": blob, "line": 0},
            )
        ],
    )


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """Build every large-file plant for `size`. `ctx` is accepted for signature
    parity (fixture-api.md); unused here."""
    del ctx
    total = _COUNTS[size]
    plants = [
        _large_blob_plant("large-file-00", _binary_fill(rng, _WARN_TIER_SIZE)),
        _lfs_pointer_plant(rng, "large-file-01"),
        _large_blob_plant("large-file-02", _binary_fill(rng, _HIGH_TIER_SIZE)),
    ]
    return plants[:total]
