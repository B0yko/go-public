"""Fictional organisation/domain/ticket/name constants shared by the deny-list and
pii plant modules and by `bench/fixture.py`'s generated `go-public.toml` (the config
must list exactly what the plants target, or the detectors have nothing to match).

Assembled from parts per conventions.md's "plant-shaped strings are assembled at
runtime", which the Data section names as covering "deny terms" too, alongside
secrets, emails, phone numbers, private IPs, user paths and internal hostnames.
`ORG_TERM`/`BOUNDARY_TERM` reuse product spec item 4's own two illustrative
examples ("Acme Corp" for variant generation, "Falcon" for the boundary rule).
"""

from __future__ import annotations

#: Product spec item 4's variant-generation example: "Acme Corp" -> "acme-corp",
#: "acme_corp", "acmecorp", "AcmeCorp".
ORG_TERM = "Ac" + "me" + " " + "Corp"
#: Product spec item 4's boundary-rule example: "AcmeCorpClient matches, falconry
#: does not match Falcon".
BOUNDARY_TERM = "Fal" + "con"
#: A word that legitimately contains `BOUNDARY_TERM` as a substring but fails the
#: boundary rule on both sides (lower-to-lower): a hard negative for the filler.
BOUNDARY_TERM_HARD_NEGATIVE = "fal" + "conry"

ORG_DOMAIN = "buildhub" + ".example"  # a reserved TLD, still a valid deny-domain target
DENY_REGEX_PATTERN = r"projx-\d{3}"
DENY_REGEX_VALUE = "projx-" + "942"
TICKET_PREFIX = "SPRO" + "CKET"
FLAGGED_NAME = "Mor" + "gan " + "Lee"

DENY_TERMS: tuple[str, ...] = (ORG_TERM, BOUNDARY_TERM)
DENY_DOMAINS: tuple[str, ...] = (ORG_DOMAIN,)
DENY_REGEXES: tuple[str, ...] = (DENY_REGEX_PATTERN,)
DENY_TICKET_KEYS: tuple[str, ...] = (TICKET_PREFIX,)
DENY_NAMES: tuple[str, ...] = (FLAGGED_NAME,)
