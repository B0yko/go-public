"""Licence-history plants (product spec item 7; stage-3.md 3b): 3 licence
transitions plus 1 proprietary/confidential notice, per the Data section's
small-seed table.

Licence body text below is ordinary open-source licence boilerplate (MIT, Apache-2.0,
BSD-3-Clause, Unlicense) — the same kind of text this very repository's own
`LICENSE` carries in full, and the whole point of that text is to be copied. None of
it needs runtime assembly (conventions.md's "plant-shaped strings" rule targets
strings a detector would otherwise flag — secrets, emails, phones, private IPs, user
paths, internal hosts, deny terms — not licence wording, which no detector in this
package classifies as a leak).
"""

from __future__ import annotations

import random

from go_public.bench.plants import FixtureContext, Plant
from go_public.bench.plants._fictional import LICENCE_FOREIGN_HOLDER
from go_public.bench.truth import ExpectedFinding

_COUNTS: dict[str, int] = {"tiny": 2, "small": 4}

_MIT_TEXT = (
    b"MIT License\n\n"
    b"Permission is hereby granted, free of charge, to any person obtaining a copy\n"
    b"of this software and associated documentation files, to deal in the Software\n"
    b"without restriction.\n"
)
_APACHE_TEXT = (
    b"Apache License\n"
    b"Version 2.0, January 2004\n\n"
    b'Licensed under the Apache License, Version 2.0 (the "License");\n'
    b"you may not use this file except in compliance with the License.\n"
)
#: The "to" side of the Apache-2.0 -> proprietary transition: a copyright line naming
#: a holder other than the fixture's configured `[licence] owner`
#: (`bench/fixture.py`'s `_fixture_config`), so `licence-foreign-holder` has a real
#: mismatch to report. "All rights reserved" with no permission-grant phrase is
#: `detect/licence.py`'s own proprietary heuristic; deliberately avoids the literal
#: words "Confidential"/"Proprietary" so it does not also trip `detect_notice`
#: (that detector is exercised by this module's separate notice plant instead).
_PROPRIETARY_TEXT = (
    f"Copyright (c) 2024 {LICENCE_FOREIGN_HOLDER}\n\n"
    "All rights reserved. Internal distribution only. No licence is granted to use, "
    "copy or distribute this software without prior written approval.\n"
).encode()
_BSD_TEXT = (
    b"Redistribution and use in source and binary forms, with or without\n"
    b"modification, are permitted provided that the following conditions are met:\n\n"
    b"Neither the name of the copyright holder nor the names of its contributors\n"
    b"may be used to endorse or promote products derived from this software.\n"
)
_UNLICENSE_TEXT = (
    b"This is free and unencumbered software released into the public domain.\n\n"
    b"Anyone is free to copy, modify, publish, use, compile, sell, or distribute\n"
    b"this software.\n"
)

#: (from, to) pairs; the second transition's "to" side also carries a foreign
#: copyright holder (see `_PROPRIETARY_TEXT`).
_TRANSITIONS: tuple[tuple[bytes, bytes, bool], ...] = (
    (_MIT_TEXT, _APACHE_TEXT, False),
    (_APACHE_TEXT, _PROPRIETARY_TEXT, True),
    (_BSD_TEXT, _UNLICENSE_TEXT, False),
)

#: A proprietary/confidential notice, planted at `head` (not a licence-relevant
#: path): `detect/licence.py`'s `detect_notice` runs over every blob's text, not
#: just licence files (stage-3.md: "licence files, SPDX/header comment blocks at
#: file top").
_NOTICE_CONTENT = (
    b"// Confidential: internal draft, do not redistribute outside the team.\n\n"
    b"// (placeholder module header)\n"
)


def _transition_plant(
    index: int, from_content: bytes, to_content: bytes, *, foreign: bool
) -> Plant:
    plant_id = f"licence-{index:02d}"
    path = f"markers/{plant_id}/LICENSE"
    expected_extra = []
    if foreign:
        expected_extra.append(
            ExpectedFinding(
                category="licence",
                eval_class="licence",
                kind="path",
                key={"path": path},
            )
        )
    return Plant(
        plant_id=plant_id,
        category="licence",
        location_type="licence_transition",
        path=path,
        from_content=from_content,
        content=to_content,
        eval_class="licence",
        rule_family="licence-transition",
        expected_extra=expected_extra,
    )


def _notice_plant(index: int) -> Plant:
    plant_id = f"licence-{index:02d}"
    return Plant(
        plant_id=plant_id,
        category="licence",
        location_type="head",
        path=f"markers/{plant_id}-notice.txt",
        content=_NOTICE_CONTENT,
        eval_class="licence",
        rule_family="licence-proprietary",
    )


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """Build every licence plant for `size`. `rng`/`ctx` accepted for signature
    parity (fixture-api.md); every plant's content is a fixed fictional value, so
    neither is needed here."""
    del rng, ctx
    total = _COUNTS[size]
    transitions = [
        _transition_plant(index, from_content, to_content, foreign=foreign)
        for index, (from_content, to_content, foreign) in enumerate(_TRANSITIONS)
    ]
    notice = _notice_plant(len(_TRANSITIONS))
    if total >= len(transitions) + 1:
        return [*transitions, notice]
    # `tiny`: fewer transitions than `_TRANSITIONS` holds, but the notice plant
    # (a different rule id, licence-proprietary) is always kept so both this
    # category's rule ids are covered even at the smallest size.
    return [*transitions[: total - 1], notice]
