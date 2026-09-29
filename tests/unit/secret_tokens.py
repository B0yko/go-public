"""Runtime-assembled synthetic secret tokens for the secrets-engine tests.

Plant-shaped strings are assembled at runtime. None of these
provider prefixes ever appears next to its generated suffix as one source-file
literal; every suffix comes from `_chars`, called at import/test time, never typed
out. Formats are the providers' own documented shapes, not sampled from the
gitleaks regex itself.
"""

from __future__ import annotations

import random
import string

_B32 = string.ascii_uppercase + "234567"
_ALNUM = string.ascii_letters + string.digits
_HEX = "0123456789abcdef"


def _chars(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def aws_access_key(rng: random.Random) -> str:
    """docs.aws.amazon.com: AKIA + 16 chars, base32-style alphabet."""
    return "AKIA" + _chars(rng, _B32, 16)


def github_pat_classic(rng: random.Random) -> str:
    """github.com/settings/tokens: ghp_ + 36 alphanumeric."""
    return "ghp_" + _chars(rng, _ALNUM, 36)


def github_pat_fine_grained(rng: random.Random) -> str:
    """docs.github.com fine-grained PAT: github_pat_ + 82 word chars."""
    return "github_pat_" + _chars(rng, _ALNUM + "_", 82)


def gitlab_pat(rng: random.Random) -> str:
    """docs.gitlab.com PAT: glpat- + 20 chars."""
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
    """stripe.com/docs/keys: sk_live_ + 24+ alphanumeric."""
    return "sk_live_" + _chars(rng, _ALNUM, 24)


def google_api_key(rng: random.Random) -> str:
    """cloud.google.com API key: AIza + 35 chars."""
    return "AIza" + _chars(rng, _ALNUM + "_-", 35)


def sendgrid_api_key(rng: random.Random) -> str:
    """docs.sendgrid.com: SG. + 66 chars."""
    return "SG." + _chars(rng, _ALNUM + "=_.-", 66)


def twilio_api_key(rng: random.Random) -> str:
    """twilio.com API key: SK + 32 hex chars."""
    return "SK" + _chars(rng, _HEX.upper(), 32)


def npm_token(rng: random.Random) -> str:
    """docs.npmjs.com: npm_ + 36 lowercase alphanumeric."""
    return "npm_" + _chars(rng, string.ascii_lowercase + string.digits, 36)


def pypi_upload_token(rng: random.Random) -> str:
    """pypi.org token: fixed 'pypi-AgEIcHlwaS5vcmc' prefix (base64 of 'pypi.org'
    plus framing bytes) then 50+ url-safe base64 chars."""
    return "pypi-AgEIcHlwaS5vcmc" + _chars(rng, _ALNUM + "-_", 60)


def shopify_access_token(rng: random.Random) -> str:
    """shopify.dev access token: shpat_ + 32 hex."""
    return "shpat_" + _chars(rng, _HEX, 32)


def digitalocean_token(rng: random.Random) -> str:
    """docs.digitalocean.com OAuth token: doo_v1_ + 64 hex."""
    return "doo_v1_" + _chars(rng, _HEX, 64)


def private_key_block(rng: random.Random) -> str:
    """A PEM-shaped block: BEGIN marker, base64-ish body >= 64 chars, END marker.
    Built from parts so no single literal in this file is the dangerous span."""
    begin = "-----" + "BEGIN" + " RSA PRIVATE KEY" + "-----"
    end = "-----" + "END" + " RSA PRIVATE KEY" + "-----"
    body = _chars(rng, _ALNUM + "+/=", 120)
    return begin + "\n" + body + "\n" + end


def generic_high_entropy_value(rng: random.Random, n: int = 32) -> str:
    """A token for the generic-entropy detector: mixed-case alnum, always
    generated, never typed out as a literal."""
    return _chars(rng, _ALNUM + "-_", n)
