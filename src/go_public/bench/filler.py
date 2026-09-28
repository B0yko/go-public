"""Realistic, finding-free filler content for fixture repositories.

Templates for the file types real repositories contain. No emails outside reserved
domains, no local paths, IPs, hostnames, secrets or binary metadata: once detectors
exist, a `--no-plants` fixture must scan to zero findings (Data section).

`hard_negatives()` adds content that looks plant-shaped but must never be flagged
(Data section's own list), so precision on the fixture means something: a detector
that fires on these would show up as a false positive in the recall/precision test,
not just in `--no-plants`.
"""

from __future__ import annotations

import json
import random
import uuid
from collections.abc import Callable

import phonenumbers

from go_public.bench.plants._fictional import BOUNDARY_TERM_HARD_NEGATIVE

_PHONE_REGIONS = ("US", "GB", "DE")

_Generator = Callable[[random.Random, str], bytes]


def python_module(rng: random.Random, name: str) -> bytes:
    magic = rng.randint(1, 1000)
    return (
        f'"""Small utility module: {name}."""\n\n\n'
        "def add(a: int, b: int) -> int:\n"
        '    """Return the sum of two integers."""\n'
        "    return a + b\n\n\n"
        f"MAGIC = {magic}\n"
    ).encode()


def javascript_module(rng: random.Random, name: str) -> bytes:
    magic = rng.randint(1, 1000)
    return (
        f"// {name}: a small helper\n"
        "function double(x) {\n"
        "  return x * 2;\n"
        "}\n\n"
        f"module.exports = {{ double, magic: {magic} }};\n"
    ).encode()


def markdown_notes(rng: random.Random, name: str) -> bytes:
    items = rng.sample(["alpha", "beta", "gamma", "delta", "epsilon"], k=3)
    body = "\n".join(f"- {item}" for item in items)
    return f"# {name}\n\n{body}\n".encode()


def yaml_config(rng: random.Random, name: str) -> bytes:
    replicas = rng.randint(1, 9)
    return f"name: {name}\nreplicas: {replicas}\nfeatures:\n  - alpha\n  - beta\n".encode()


def json_document(rng: random.Random, name: str) -> bytes:
    doc = {"name": name, "value": rng.randint(1, 1000)}
    return (json.dumps(doc, indent=2) + "\n").encode()


def notebook(rng: random.Random, name: str) -> bytes:
    doc = {
        "cells": [
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [f"print({rng.randint(1, 100)!r})\n"],
            }
        ],
        "metadata": {"language_info": {"name": "python"}, "title": name},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    return (json.dumps(doc, indent=1) + "\n").encode()


def svg_image(rng: random.Random, name: str) -> bytes:
    radius = rng.randint(10, 40)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
        f'<circle cx="50" cy="50" r="{radius}" /><title>{name}</title></svg>\n'
    ).encode()


def lockfile(rng: random.Random, name: str) -> bytes:
    version = f"{rng.randint(1, 9)}.{rng.randint(0, 20)}.{rng.randint(0, 20)}"
    integrity = (
        "sha512-"
        + "".join(
            rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
            for _ in range(64)
        )
        + "=="
    )
    doc = {
        "name": name,
        "lockfileVersion": 3,
        "packages": {"": {"version": version, "integrity": integrity}},
    }
    return (json.dumps(doc, indent=2) + "\n").encode()


def _looks_like_a_phone_number(digits: str) -> bool:
    """A random digit run can coincidentally be (or contain) a valid phone number in
    some region (plain 10-digit runs are often valid NANP numbers); check with the
    same library `detect/pii.py` uses so this hard negative is a true negative
    regardless of the digits `rng` happens to pick, rather than relying on a length
    or prefix that "usually" avoids it.
    """
    text = f"an order number that looks like a phone number: {digits}"
    return any(
        list(phonenumbers.PhoneNumberMatcher(text, region, leniency=phonenumbers.Leniency.VALID))
        for region in _PHONE_REGIONS
    )


def _non_phone_order_number(rng: random.Random) -> str:
    for _ in range(50):
        digits = "".join(rng.choice("0123456789") for _ in range(10))
        if not _looks_like_a_phone_number(digits):
            return digits
    raise AssertionError("could not find a non-phone-shaped order number in 50 tries")


def hard_negatives(rng: random.Random, name: str) -> bytes:
    """Content that looks plant-shaped but is not: every bullet the Data section
    names, so a detector that fires here shows up as a false positive.
    """
    order_number = _non_phone_order_number(rng)
    git_sha = "".join(rng.choice("0123456789abcdef") for _ in range(40))
    data_uri = (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lE"
        "QVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    )
    return (
        f"# {name}\n\n"
        "Notes on strings that must never be flagged:\n\n"
        "- an example.com email: pat@example.com (also the allowlisted identity)\n"
        f"- a UUID: {uuid.UUID(int=rng.getrandbits(128))}\n"
        f"- a git commit SHA: {git_sha}\n"
        f"- a base64 data URI: {data_uri}\n"
        "- a placeholder API key: YOUR_API_KEY_HERE\n"
        "- a run of x placeholders: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
        "- loopback: 127.0.0.1\n"
        "- an IP-like version string: 1.2.3.4\n"
        "- a common install prefix: /usr/local/bin\n"
        f"- an order number that looks like a phone number: {order_number}\n"
        f"- a word containing a deny term as a substring: {BOUNDARY_TERM_HARD_NEGATIVE}\n"
        "- an MIT licence quoted inside a vendored file's docs:\n"
        '  "Permission is hereby granted, free of charge, to any person obtaining a\n'
        '  copy of this software..."\n'
    ).encode()


#: (repo-relative path, generator) pairs used by `generate`, in commit order.
TEMPLATES: tuple[tuple[str, _Generator], ...] = (
    ("src/util.py", python_module),
    ("src/helper.js", javascript_module),
    ("project-notes.md", markdown_notes),
    ("config/settings.yaml", yaml_config),
    ("data/info.json", json_document),
    ("notebooks/analysis.ipynb", notebook),
    ("assets/logo.svg", svg_image),
    ("package-lock.json", lockfile),
    ("docs/hard-negatives.md", hard_negatives),
)


def generate(rng: random.Random) -> list[tuple[str, bytes]]:
    """One filler file per template, content varying deterministically with `rng`."""
    return [(path, gen(rng, path.rsplit("/", 1)[-1])) for path, gen in TEMPLATES]
