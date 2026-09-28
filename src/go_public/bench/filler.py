"""Realistic, finding-free filler content for fixture repositories.

Templates for the file types real repositories contain. No emails outside reserved
domains, no local paths, IPs, hostnames, secrets or binary metadata: once detectors
exist, a `--no-plants` fixture must scan to zero findings (Data section).
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable

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
    doc = {"name": name, "lockfileVersion": 3, "packages": {"": {"version": version}}}
    return (json.dumps(doc, indent=2) + "\n").encode()


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
)


def generate(rng: random.Random) -> list[tuple[str, bytes]]:
    """One filler file per template, content varying deterministically with `rng`."""
    return [(path, gen(rng, path.rsplit("/", 1)[-1])) for path, gen in TEMPLATES]
