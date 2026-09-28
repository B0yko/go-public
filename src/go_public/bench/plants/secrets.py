"""Secret plants for the fixture generator (product spec item 2 / "Plant formats";
stage-2.md 2b).

Every token follows its provider's own documented format (prefix, character set,
length) — the doc URL is in a comment next to each generator — and is assembled at
runtime from parts, never typed out as one literal (conventions.md: "Plant-shaped
strings are assembled at runtime"). No token is sampled from the vendored rule's own
regex, and no AI-vendor key format is used, per stage-2.md.

`generate()` only builds and returns `Plant` objects; `bench/fixture.py` is the one
that calls `ctx.place()` for each, exactly as it already does for marker plants.
`ctx` is accepted (fixture-api.md's `generate(rng, ctx) -> list[Plant]`) for parity
with future plant modules that need it (e.g. to assign a specific identity); this
module does not use it. The `size` keyword is this module's own extension of that
signature — fixture-api.md predates size-dependent plant counts (stage-2.md's
"Provide counts for size small too").
"""

from __future__ import annotations

import random
import string
from collections.abc import Callable

from go_public.bench.plants import FixtureContext, LocationType, Plant

_B32 = string.ascii_uppercase + "234567"
_ALNUM = string.ascii_letters + string.digits
_HEX = "0123456789abcdef"

#: `refs/original/refs/heads/main` is a single fixed ref name (unlike `replace`,
#: which is keyed by an oid that changes as `main` advances, or `tag_only`, whose
#: tag name embeds the plant id): at most one plant, ever, across every category, may
#: target `original` in one fixture build, or the second `update-ref` silently
#: overwrites the first (its commit becomes unreferenced instead of "on no branch").
#: This module always plants exactly one thing there (index 0, below); `fixture.py`
#: excludes `original` from its own marker placement for exactly this reason.
_SINGLETON_LOCATION: LocationType = "original"

#: The other 11 location types stage-2.md names for secret plants (path_name/
#: binary_field/ref_name are left to the categories that will actually use them:
#: org-identifier and binary-metadata, stage 3), cycled for indices after 0.
_REPEATABLE_LOCATIONS: tuple[LocationType, ...] = (
    "head",
    "history_only",
    "side_branch",
    "tag_only",
    "notes",
    "stash",
    "remote_tracking",
    "replace",
    "commit_message",
    "tag_message",
    "unreachable",
)

_MESSAGE_LOCATIONS = frozenset({"commit_message", "tag_message"})


def _location_for(index: int) -> LocationType:
    if index == 0:
        return _SINGLETON_LOCATION
    return _REPEATABLE_LOCATIONS[(index - 1) % len(_REPEATABLE_LOCATIONS)]


def _generic_slots(total: int, generic_count: int) -> set[int]:
    """Indices (never 0, the singleton) whose location can carry assignment-style
    content (excludes `commit_message`/`tag_message`, plain-sentence locations)."""
    slots: set[int] = set()
    for index in range(1, total):
        if len(slots) >= generic_count:
            break
        if _location_for(index) not in _MESSAGE_LOCATIONS:
            slots.add(index)
    return slots


def _chars(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def aws_access_key(rng: random.Random) -> str:
    """docs.aws.amazon.com IAM access keys: AKIA + 16 base32-style chars."""
    return "AKIA" + _chars(rng, _B32, 16)


def github_pat_classic(rng: random.Random) -> str:
    """github.com/settings/tokens classic PAT: ghp_ + 36 alphanumeric."""
    return "ghp_" + _chars(rng, _ALNUM, 36)


def github_pat_fine_grained(rng: random.Random) -> str:
    """docs.github.com fine-grained PAT: github_pat_ + 82 word characters."""
    return "github_pat_" + _chars(rng, _ALNUM + "_", 82)


def gitlab_pat(rng: random.Random) -> str:
    """docs.gitlab.com personal access token: glpat- + 20 characters."""
    return "glpat-" + _chars(rng, _ALNUM + "-_", 20)


def slack_bot_token(rng: random.Random) -> str:
    """api.slack.com bot token: xoxb-digits-digits-alnum."""
    return (
        "xoxb-"
        + _chars(rng, string.digits, 11)
        + "-"
        + _chars(rng, string.digits, 11)
        + _chars(rng, _ALNUM + "-", 24)
    )


def slack_webhook_url(rng: random.Random) -> str:
    """api.slack.com incoming webhook: hooks.slack.com/services/<token>."""
    return "hooks.slack.com/services/" + _chars(rng, _ALNUM + "+/", 50)


def stripe_secret_key(rng: random.Random) -> str:
    """stripe.com/docs/keys live secret key: sk_live_ + 24+ alphanumeric."""
    return "sk_live_" + _chars(rng, _ALNUM, 24)


def google_api_key(rng: random.Random) -> str:
    """cloud.google.com API key: AIza + 35 characters."""
    return "AIza" + _chars(rng, _ALNUM + "_-", 35)


def sendgrid_api_key(rng: random.Random) -> str:
    """docs.sendgrid.com API key: SG. + 66 characters."""
    return "SG." + _chars(rng, _ALNUM + "=_.-", 66)


def twilio_api_key(rng: random.Random) -> str:
    """twilio.com API key: SK + 32 hex characters."""
    return "SK" + _chars(rng, _HEX.upper(), 32)


def npm_token(rng: random.Random) -> str:
    """docs.npmjs.com access token: npm_ + 36 lowercase alphanumeric."""
    return "npm_" + _chars(rng, string.ascii_lowercase + string.digits, 36)


def pypi_upload_token(rng: random.Random) -> str:
    """pypi.org API token: fixed 'pypi-AgEIcHlwaS5vcmc' prefix (base64 framing for
    'pypi.org') then 50+ url-safe base64 characters."""
    return "pypi-AgEIcHlwaS5vcmc" + _chars(rng, _ALNUM + "-_", 60)


def shopify_access_token(rng: random.Random) -> str:
    """shopify.dev access token: shpat_ + 32 hex characters."""
    return "shpat_" + _chars(rng, _HEX, 32)


def digitalocean_token(rng: random.Random) -> str:
    """docs.digitalocean.com OAuth token: doo_v1_ + 64 hex characters."""
    return "doo_v1_" + _chars(rng, _HEX, 64)


def private_key_block(rng: random.Random) -> str:
    """A PEM-shaped block: BEGIN marker, base64-ish body, END marker. Built from
    parts so no literal in this file is the dangerous span itself."""
    begin = "-----" + "BEGIN" + " RSA PRIVATE KEY" + "-----"
    end = "-----" + "END" + " RSA PRIVATE KEY" + "-----"
    body = _chars(rng, _ALNUM + "+/=", 120)
    return begin + "\n" + body + "\n" + end


def generic_secret_value(rng: random.Random, n: int = 32) -> str:
    """A token for go-public's own `generic-entropy` detector: mixed-case
    alphanumeric, always generated, never a literal in source."""
    return _chars(rng, _ALNUM + "-_", n)


#: (rule_id, generator, assignment-style template) for every vendor family. Values
#: matter, not the surrounding template: each has been verified (stage 2a's own
#: `tests/unit/test_secrets_engine.py`) to fire with exactly this `rule_id`.
_VENDOR_FAMILIES: tuple[tuple[str, Callable[[random.Random], str], str], ...] = (
    ("aws-access-token", aws_access_key, 'access_key = "{}"\n'),
    ("github-pat", github_pat_classic, 'token = "{}"\n'),
    ("github-fine-grained-pat", github_pat_fine_grained, 'token = "{}"\n'),
    ("gitlab-pat", gitlab_pat, 'token = "{}"\n'),
    ("slack-bot-token", slack_bot_token, 'token = "{}"\n'),
    ("slack-webhook-url", slack_webhook_url, 'url = "https://{}"\n'),
    ("stripe-access-token", stripe_secret_key, 'key = "{}"\n'),
    ("gcp-api-key", google_api_key, 'key = "{}"\n'),
    ("sendgrid-api-token", sendgrid_api_key, 'key = "{}"\n'),
    ("twilio-api-key", twilio_api_key, 'key = "{}"\n'),
    ("npm-access-token", npm_token, 'token = "{}"\n'),
    ("pypi-upload-token", pypi_upload_token, 'token = "{}"\n'),
    ("shopify-access-token", shopify_access_token, 'token = "{}"\n'),
    ("digitalocean-access-token", digitalocean_token, 'token = "{}"\n'),
    ("private-key", private_key_block, "{}\n"),
)

_GENERIC_TEMPLATE = 'credential = "{}"\n'

#: `size` -> (vendor plant count, generic plant count), per the product spec's
#: "Plants per `small` seed" table (secret: 20 across >= 10 families, plus 4
#: generic-entropy) and stage-2.md's tiny guidance (one per location type, >= 10
#: families).
_COUNTS: dict[str, tuple[int, int]] = {"tiny": (10, 2), "small": (20, 4)}


def _vendor_plant(index: int, location_type: LocationType, token: str, rule_id: str) -> Plant:
    plant_id = f"secret-{rule_id}-{index:02d}"
    if location_type in _MESSAGE_LOCATIONS:
        return Plant(
            plant_id=plant_id,
            category="secret",
            location_type=location_type,
            message=f"chore: rotate leaked credential {token}",
            eval_class="secret-vendor",
            rule_family=rule_id,
        )
    template = next(t for rid, _gen, t in _VENDOR_FAMILIES if rid == rule_id)
    return Plant(
        plant_id=plant_id,
        category="secret",
        location_type=location_type,
        content=template.format(token).encode(),
        eval_class="secret-vendor",
        rule_family=rule_id,
    )


def _generic_plant(index: int, location_type: LocationType, value: str) -> Plant:
    plant_id = f"secret-generic-entropy-{index:02d}"
    return Plant(
        plant_id=plant_id,
        category="secret",
        location_type=location_type,
        content=_GENERIC_TEMPLATE.format(value).encode(),
        eval_class="secret-generic",
        rule_family="generic-entropy",
    )


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """Build every secret plant for `size` ("tiny" or "small"). `ctx` is accepted for
    signature parity with other plant modules; unused here.

    Every plant gets one index in `range(total)`; `_location_for` maps that index to
    a location type (index 0 always the `original` singleton, the rest cycling
    through the other 11 types), and `_generic_slots` picks which non-message
    indices carry a generic-entropy plant instead of a vendor one.
    """
    del ctx
    vendor_count, generic_count = _COUNTS[size]
    total = vendor_count + generic_count
    generic_indices = _generic_slots(total, generic_count)

    plants: list[Plant] = []
    vendor_i = generic_i = 0
    for index in range(total):
        location_type = _location_for(index)
        if index in generic_indices:
            plants.append(_generic_plant(generic_i, location_type, generic_secret_value(rng)))
            generic_i += 1
        else:
            rule_id, generator, _template = _VENDOR_FAMILIES[vendor_i % len(_VENDOR_FAMILIES)]
            plants.append(_vendor_plant(vendor_i, location_type, generator(rng), rule_id))
            vendor_i += 1
    return plants
