"""Blind-spot plants (product spec Data section): things a static, offline scanner is
not expected to catch. They are reported separately (`truth.blind.jsonl`, measured by
`go-public bench --blind-spots`) and never counted in the main table.

Each plant sits at HEAD in its own file. `eval_class` names the blind-spot kind; the
expected finding's `category` is what a detector would have to report for the plant
to count as caught (matched on the blob, since some of these have no meaningful line).
"""

from __future__ import annotations

import base64
import io
import random
import zipfile

from PIL import Image, ImageDraw, ImageFont

from go_public.bench.plants import FixtureContext, Plant
from go_public.bench.plants._fictional import ORG_TERM
from go_public.bench.plants.secrets import (
    generic_secret_value,
    github_pat_classic,
    npm_token,
    stripe_secret_key,
)

#: Every blind-spot plant id starts with this; `bench/fixture.py` uses it to route a
#: resolved plant to `truth.blind.jsonl` instead of `truth.jsonl`.
BLIND_PREFIX = "blind-"

#: The blind-spot kinds, in a fixed order (also the order of the results table).
KINDS: tuple[str, ...] = (
    "split-secret",
    "base64-secret",
    "zipped-secret",
    "minified-generic",
    "image-text",
    "spaced-deny-term",
    "xmp-gps",
)


def _split_secret(rng: random.Random) -> tuple[str, bytes, str]:
    token = github_pat_classic(rng)
    cut = len(token) // 2
    code = f'_first = "{token[:cut]}"\n_second = "{token[cut:]}"\ncredential = _first + _second\n'
    return "blind/split_secret.py", code.encode(), "secret"


def _base64_secret(rng: random.Random) -> tuple[str, bytes, str]:
    token = stripe_secret_key(rng)
    encoded = base64.b64encode(token.encode()).decode()
    return "blind/encoded.yaml", f"payload: {encoded}\n".encode(), "secret"


def _zipped_secret(rng: random.Random) -> tuple[str, bytes, str]:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("config/settings.txt", date_time=(2024, 1, 1, 0, 0, 0))
        archive.writestr(info, f'token = "{npm_token(rng)}"\n')
    return "blind/bundle.zip", buffer.getvalue(), "secret"


def _minified_generic(rng: random.Random) -> tuple[str, bytes, str]:
    words = ["a", "b", "c", "d", "e", "f", "g", "h"]
    chunks: list[str] = []
    while sum(len(c) for c in chunks) < 900:
        chunks.append(f"var {rng.choice(words)}{rng.randint(0, 999)}={rng.randint(0, 99999)};")
    chunks.append(f'var credential="{generic_secret_value(rng)}";')
    while sum(len(c) for c in chunks) < 2000:
        chunks.append(f"var {rng.choice(words)}{rng.randint(0, 999)}={rng.randint(0, 99999)};")
    return "blind/bundle.min.js", ("".join(chunks) + "\n").encode(), "secret"


def _image_text(rng: random.Random) -> tuple[str, bytes, str]:
    token = github_pat_classic(rng)
    image = Image.new("RGB", (420, 40), "white")
    ImageDraw.Draw(image).text((6, 12), token, fill="black", font=ImageFont.load_default())
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return "blind/screenshot.png", buffer.getvalue(), "secret"


def _spaced_deny_term(rng: random.Random) -> tuple[str, bytes, str]:
    del rng
    spaced = " ".join(ORG_TERM.replace(" ", ""))
    return "blind/spaced.md", f"Internal codename: {spaced}\n".encode(), "org-identifier"


def _xmp_gps(rng: random.Random) -> tuple[str, bytes, str]:
    lat = f"{rng.randint(10, 60)},{rng.randint(0, 59)}.{rng.randint(100, 999)}N"
    lon = f"{rng.randint(10, 170)},{rng.randint(0, 59)}.{rng.randint(100, 999)}E"
    xml = (
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">\n'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
        '<rdf:Description xmlns:exif="http://ns.adobe.com/exif/1.0/"\n'
        f'  exif:GPSLatitude="{lat}" exif:GPSLongitude="{lon}"/>\n'
        "</rdf:RDF>\n</x:xmpmeta>\n"
    )
    return "blind/photo.xmp", xml.encode(), "binary-metadata"


_BUILDERS = {
    "split-secret": _split_secret,
    "base64-secret": _base64_secret,
    "zipped-secret": _zipped_secret,
    "minified-generic": _minified_generic,
    "image-text": _image_text,
    "spaced-deny-term": _spaced_deny_term,
    "xmp-gps": _xmp_gps,
}


def generate(rng: random.Random, ctx: FixtureContext, *, size: str = "small") -> list[Plant]:
    """One plant per blind-spot kind, each in its own file at HEAD."""
    del ctx, size
    plants = []
    for kind in KINDS:
        path, content, category = _BUILDERS[kind](rng)
        plants.append(
            Plant(
                plant_id=f"{BLIND_PREFIX}{kind}",
                category=category,
                location_type="head",
                path=path,
                content=content,
                eval_class=f"blind-{kind}",
                rule_family=kind,
            )
        )
    return plants
