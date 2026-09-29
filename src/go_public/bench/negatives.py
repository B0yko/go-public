"""Hard negatives: content shaped like a plant that no detector may flag.

The product spec's Data section asks for about 150 of these per seed so that
precision means something. `generate(rng, per_kind)` returns one small file per
kind (16 kinds); `per_kind=10` gives 160 items (`small`), `per_kind=2` gives 32
(`tiny`). Every item is built from parts at runtime, seeded, and checked against
the detectors' own definitions where a random draw could accidentally cross the
line (phone-shaped digit runs). A `--no-plants` fixture must scan to zero findings.
"""

from __future__ import annotations

import base64
import json
import random
import struct
import uuid
import zlib
from collections.abc import Callable

import phonenumbers

from go_public.bench.plants._fictional import BOUNDARY_TERM_HARD_NEGATIVE

_PHONE_REGIONS = ("US", "GB", "DE")
_WORDS = (
    "build",
    "docs",
    "release",
    "support",
    "hello",
    "team",
    "ops",
    "web",
    "mail",
    "notes",
    "status",
    "triage",
    "review",
    "design",
    "sync",
    "intake",
)
_HEX = "0123456789abcdef"

Item = Callable[[random.Random], str]


def _word(rng: random.Random) -> str:
    return f"{rng.choice(_WORDS)}{rng.randint(1, 99)}"


def _hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(_HEX) for _ in range(n))


def _looks_like_a_phone_number(digits: str) -> bool:
    text = f"an order number that looks like a phone number: {digits}"
    return any(
        list(phonenumbers.PhoneNumberMatcher(text, region, leniency=phonenumbers.Leniency.VALID))
        for region in _PHONE_REGIONS
    )


def non_phone_digits(rng: random.Random, length: int = 10) -> str:
    """A digit run of `length` that `phonenumbers` accepts in none of the scanned
    regions, so it stays a negative whatever `rng` draws."""
    for _ in range(200):
        digits = "".join(rng.choice("0123456789") for _ in range(length))
        if not _looks_like_a_phone_number(digits):
            return digits
    raise AssertionError("could not find a non-phone-shaped digit run in 200 tries")


def phone_valid_digits(rng: random.Random, length: int) -> str:
    """A digit run of `length` that `phonenumbers` does accept as a national number in
    one of the scanned regions: the run only stays a negative because it is bare (no
    separator, no trunk prefix) or sits in a lockfile."""
    for _ in range(2000):
        digits = str(rng.randint(2, 9)) + "".join(
            rng.choice("0123456789") for _ in range(length - 1)
        )
        if _looks_like_a_phone_number(digits):
            return digits
    # Short runs are rarely valid (about 1 in 2000 at 7 digits), so random draws can
    # all miss. Walk up from a random start instead: the walk is deterministic in `rng`
    # and only runs for seeds that would otherwise fail.
    low, high = 2 * 10 ** (length - 1), 10**length
    start = rng.randrange(low, high)
    for offset in range(high - low):
        digits = str(low + (start - low + offset) % (high - low))
        if _looks_like_a_phone_number(digits):
            return digits
    raise AssertionError(f"no phone-valid digit run of length {length}")


def _tiny_png(rng: random.Random) -> bytes:
    """A valid 1x1 PNG in a random colour, with no ancillary chunks."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    pixel = b"\x00" + bytes(rng.randrange(256) for _ in range(3))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(pixel))
        + chunk(b"IEND", b"")
    )


# -- one generator per kind ------------------------------------------------------------


def _example_email(rng: random.Random) -> str:
    tld = rng.choice(("example.com", "example.org", "example.net"))
    return f"- write to {_word(rng)}@{tld} for questions"


def _public_identity(rng: random.Random) -> str:
    style = rng.choice(("Author", "Maintainer", "Reviewed by", "Contact"))
    return f"- {style}: Pat Public <pat@example.com>"


def _uuid(rng: random.Random) -> str:
    return f'    "{_word(rng)}": "{uuid.UUID(int=rng.getrandbits(128))}"'


def _git_sha(rng: random.Random) -> str:
    if rng.random() < 0.7:
        return f"  - repo: https://github.com/example/{_word(rng)}\n    rev: {_hex(rng, 40)}"
    return f"  - short: {_hex(rng, 7)}  # abbreviated commit id"


def _data_uri(rng: random.Random) -> str:
    payload = base64.b64encode(_tiny_png(rng)).decode()
    return f"- ![pixel {rng.randint(1, 99)}](data:image/png;base64,{payload})"


def _integrity(rng: random.Random) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    if rng.random() < 0.5:
        digest = "".join(rng.choice(alphabet) for _ in range(86)) + "=="
        algo = "sha512"
    else:
        digest = "".join(rng.choice(alphabet) for _ in range(27)) + "="
        algo = "sha1"
    name = _word(rng)
    return (
        f'    "node_modules/{name}": {{"version": "{rng.randint(1, 9)}.{rng.randint(0, 20)}.'
        f'{rng.randint(0, 20)}", "resolved": "https://registry.npmjs.org/{name}/-/{name}.tgz", '
        f'"integrity": "{algo}-{digest}"}}'
    )


def _placeholder(rng: random.Random) -> str:
    choice = rng.randrange(6)
    if choice == 0:
        return "api_key: YOUR_API_KEY_HERE"
    if choice == 1:
        return f"token: {'x' * rng.randint(16, 40)}"
    if choice == 2:
        return "secret: <your-secret-here>"
    if choice == 3:
        return "password: ${DB_PASSWORD}"
    if choice == 4:
        return "client_secret: REPLACE_ME"
    return "auth_token: changeme"


def _loopback(rng: random.Random) -> str:
    port = rng.choice((3000, 5000, 8000, 8080, 9090))
    host = rng.choice(("127.0.0.1", "localhost"))
    return f"- run the dev server on http://{host}:{port}/ and open it in a browser"


def _ip_like_version(rng: random.Random) -> str:
    # First octet 1-9 keeps these outside every private range.
    parts = [rng.randint(1, 9)] + [rng.randint(0, 30) for _ in range(3)]
    return f"- release {'.'.join(str(p) for p in parts)} (build number, not an address)"


def _install_path(rng: random.Random) -> str:
    base = rng.choice(("/usr/local/bin", "/usr/bin", "/opt/tools/bin", "/usr/share/doc"))
    return f"- installs `{_word(rng)}` into {base}"


def _order_number(rng: random.Random) -> str:
    if rng.random() < 0.5:
        digits = non_phone_digits(rng)
    else:  # bare 7-10 digit runs that phonenumbers would take for a national number
        digits = phone_valid_digits(rng, rng.randint(7, 10))
    return f"- order #{digits} shipped on 2024-{rng.randint(1, 12):02d}-15"


def _lockfile_size(rng: random.Random) -> str:
    name = _word(rng)
    size = phone_valid_digits(rng, rng.randint(7, 10))
    return (
        f'  {{ url = "https://files.example.org/{name}-1.{rng.randint(0, 9)}-py3-none-any.whl", '
        f"size = {size} }},"
    )


def _deny_substring(rng: random.Random) -> str:
    sentence = rng.choice(
        (
            "- the guild teaches {w} to newcomers",
            "- a history of {w} in the region",
            "- {w} equipment is stored in the annex",
            "- weekend course: introduction to {w}",
        )
    )
    return sentence.format(w=BOUNDARY_TERM_HARD_NEGATIVE)


_MIT_QUOTE = (
    "Permission is hereby granted, free of charge, to any person obtaining a copy of this software"
)


def _mit_quote(rng: random.Random) -> str:
    return f"> {_MIT_QUOTE} ({_word(rng)}; quoted from the upstream docs)"


def _assignment_lookalike(rng: random.Random) -> str:
    name = rng.choice(("password", "api_key", "secret_key", "auth_token", "client_secret"))
    value = rng.choice(
        (
            "getpass.getpass()",
            'os.environ.get("APP_VALUE")',
            "None",
            '""',
            "load_from_vault()",
            f'"{name}"',
        )
    )
    return f"{name}_{rng.randint(1, 99)} = {value}"


def _misc(rng: random.Random) -> str:
    choice = rng.randrange(4)
    if choice == 0:
        return f"- brand colour: #{_hex(rng, 6)}"
    if choice == 1:
        return f"- reference: ISBN 978-{rng.randint(0, 9)}-{rng.randint(10, 99)}-148410-0"
    if choice == 2:
        return f"- deployed at 2024-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}T10:30:00Z"
    return f"- checksum of the tarball is {_hex(rng, 64)}"


#: (path, heading, item generator). The order is the order files are committed in.
KINDS: tuple[tuple[str, str, Item], ...] = (
    ("docs/contacts.md", "# Contacts", _example_email),
    ("docs/authorship.md", "# Authorship", _public_identity),
    ("data/identifiers.json", "", _uuid),
    ("config/pins.yaml", "pins:", _git_sha),
    ("docs/inline-images.md", "# Inline images", _data_uri),
    ("vendor/lock-excerpt.json", "", _integrity),
    ("config/settings.sample.yaml", "# Sample settings (placeholders only)", _placeholder),
    ("docs/local-dev.md", "# Local development", _loopback),
    ("docs/versions.md", "# Versions", _ip_like_version),
    ("docs/install-paths.md", "# Install locations", _install_path),
    ("docs/orders.md", "# Order log", _order_number),
    ("docs/wildlife.md", "# Wildlife club", _deny_substring),
    ("vendor/upstream/README.md", "# Upstream notes", _mit_quote),
    ("src/settings_loader.py", '"""Settings loader stubs."""', _assignment_lookalike),
    ("docs/misc.md", "# Miscellaneous", _misc),
    ("uv.lock", "wheels = [", _lockfile_size),
)


def generate(rng: random.Random, per_kind: int) -> list[tuple[str, bytes]]:
    """One file per kind with `per_kind` items each (16 kinds, so `16 * per_kind`
    negatives in total)."""
    files: list[tuple[str, bytes]] = []
    for path, heading, item in KINDS:
        items = [item(rng) for _ in range(per_kind)]
        if path.endswith(".json"):
            body = "{\n" + ",\n".join(items) + "\n}\n"
            json.loads(body)  # a malformed template should fail loudly, not scan oddly
        elif path.endswith(".py"):
            body = f"{heading}\n\nimport getpass\nimport os\n\n" + "\n".join(items) + "\n"
        else:
            body = f"{heading}\n\n" + "\n".join(items) + "\n"
        files.append((path, body.encode()))
    return files
