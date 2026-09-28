"""Org-identifier plants: deny-list terms (with variants and the boundary rule),
domains, raw regexes and ticket keys (product spec item 4; stage-3.md). Covers the
`ref_name` and `path_name` location types, as stage-3.md calls for.
"""

from __future__ import annotations

import random

from go_public.bench.plants import FixtureContext, LocationType, Plant, blob_id
from go_public.bench.plants._fictional import (
    DENY_REGEX_VALUE,
    ORG_DOMAIN,
    ORG_TERM,
    TICKET_PREFIX,
)
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

#: `"Acme Corp"` -> `"acme-corp"`, `"acme_corp"`, `"acmecorp"`, and the term written
#: out plainly; `_CAMEL_CASE_FORM` is the boundary-pass example from product spec
#: item 4 ("AcmeCorpClient matches").
_VARIANT_FORMS: tuple[str, ...] = (
    ORG_TERM.replace(" ", "-"),
    ORG_TERM.replace(" ", "_"),
    ORG_TERM.replace(" ", ""),
    ORG_TERM,
)
_CAMEL_CASE_FORM = ORG_TERM.replace(" ", "") + "Client"

_COUNTS: dict[str, int] = {"tiny": 5, "small": 15}


def _term_plant(index: int, location_type: LocationType) -> Plant:
    forms = (*_VARIANT_FORMS, _CAMEL_CASE_FORM)
    text = forms[index % len(forms)]
    content = f'owner = "{text}"\n'.encode()
    return Plant(
        plant_id=f"org-identifier-term-{index:02d}",
        category="org-identifier",
        location_type=location_type,
        content=content,
        eval_class="org-identifier",
        rule_family="deny-term",
    )


def _domain_plant(index: int, location_type: LocationType) -> Plant:
    content = f'homepage = "https://{ORG_DOMAIN}/docs"\n'.encode()
    # `ORG_DOMAIN` is also configured as `[network] internal_suffixes`... no: it is
    # itself one of `[deny] domains`, and `detect/paths_network.py`'s internal-host
    # check independently flags "any host under a deny-list domain" (product spec
    # item 5) — so this same span is a real secondary network finding, not a false
    # positive.
    secondary_kind = "unreachable_blob" if location_type == "unreachable" else "blob"
    blob = blob_id(content)
    return Plant(
        plant_id=f"org-identifier-domain-{index:02d}",
        category="org-identifier",
        location_type=location_type,
        content=content,
        eval_class="org-identifier",
        rule_family="deny-domain",
        expected_extra=[
            ExpectedFinding(
                category="network",
                eval_class="network",
                kind=secondary_kind,
                key={"blob": blob, "line": 1},
            )
        ],
    )


def _regex_plant(index: int, location_type: LocationType) -> Plant:
    content = f'codename = "{DENY_REGEX_VALUE}"\n'.encode()
    return Plant(
        plant_id=f"org-identifier-regex-{index:02d}",
        category="org-identifier",
        location_type=location_type,
        content=content,
        eval_class="org-identifier",
        rule_family="deny-regex",
    )


def _ticket_plant(index: int, location_type: LocationType) -> Plant:
    content = f'ticket = "{TICKET_PREFIX}-482"\n'.encode()
    return Plant(
        plant_id=f"org-identifier-ticket-{index:02d}",
        category="org-identifier",
        location_type=location_type,
        content=content,
        eval_class="org-identifier",
        rule_family="deny-ticket",
    )


def _path_name_plant() -> Plant:
    slug = ORG_TERM.replace(" ", "-").lower()
    return Plant(
        plant_id="org-identifier-path-name",
        category="org-identifier",
        location_type="path_name",
        path=f"{slug}/README.md",
        content=b"# project notes\n",
        # `_blob_commit`'s default commit message embeds the path itself ("chore:
        # add <path>"), which would put the deny term in the commit message too and
        # produce an extra, undeclared org-identifier finding there. An explicit,
        # neutral message keeps this plant's only finding the intended path-kind one.
        message="chore: add project file",
        eval_class="org-identifier",
        rule_family="deny-term",
    )


def _ref_name_plant() -> Plant:
    slug = ORG_TERM.replace(" ", "-").lower()
    return Plant(
        plant_id="org-identifier-ref-name",
        category="org-identifier",
        location_type="ref_name",
        ref_name=f"refs/heads/{slug}/experiment",
        eval_class="org-identifier",
        rule_family="deny-term",
    )


_BUILDERS = (_term_plant, _term_plant, _domain_plant, _regex_plant, _ticket_plant)


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """Build every org-identifier plant for `size`. `rng`/`ctx` are accepted for
    signature parity (fixture-api.md); every string here is fixed (assembled from
    parts, never RNG-sampled), so both are unused."""
    del rng, ctx
    total = _COUNTS[size]
    plants: list[Plant] = [_path_name_plant(), _ref_name_plant()]
    index = 0
    while len(plants) < total:
        builder = _BUILDERS[index % len(_BUILDERS)]
        location_type = _CONTENT_LOCATIONS[index % len(_CONTENT_LOCATIONS)]
        plants.append(builder(index, location_type))
        index += 1
    return plants
