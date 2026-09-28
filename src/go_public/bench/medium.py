"""The `medium` fixture: a runtime-sized repository, finding-free filler only.

Seed 100 targets the product spec's shape: about 3,000 commits, 4 branches, 30 tags,
about 12,000 unique blobs, about 200 MB of blob content, 40 binaries. Text blobs are
assembled from fixed line pools (so 200 MB generates in seconds) with a per-blob header
that keeps every blob unique. The pools avoid every word a secret rule keys on
(`key`, `token`, `secret`, `password`, ...), so a `medium` fixture scans to zero findings
like any `--no-plants` fixture. Binaries are metadata-free PNG/JPEG noise below the
fixture config's large-file warning threshold.
"""

from __future__ import annotations

import io
import random
from dataclasses import dataclass

from PIL import Image

from go_public.bench.plants import FixtureContext

MAIN = "refs/heads/main"

_VOCAB = [
    "alpha",
    "beta",
    "gamma",
    "delta",
    "orbit",
    "lantern",
    "meadow",
    "harbor",
    "quartz",
    "timber",
    "velvet",
    "copper",
    "willow",
    "ember",
    "granite",
    "juniper",
    "kettle",
    "lattice",
    "mosaic",
    "nimbus",
    "outpost",
    "prairie",
    "ripple",
    "summit",
    "thistle",
    "upland",
    "vertex",
    "wander",
    "yonder",
    "zephyr",
    "anchor",
    "bridge",
    "canyon",
    "dune",
    "estuary",
    "fjord",
    "glacier",
    "hollow",
    "island",
    "jetty",
    "knoll",
    "lagoon",
    "marsh",
    "nook",
    "oasis",
    "peak",
    "quarry",
    "reef",
    "shoal",
    "tundra",
    "valley",
]
_VERBS = [
    "load",
    "parse",
    "merge",
    "render",
    "format",
    "split",
    "join",
    "clamp",
    "scale",
    "shift",
    "filter",
    "group",
]


def _ident(rng: random.Random) -> str:
    return f"{rng.choice(_VOCAB)}_{rng.choice(_VOCAB)}"


def _python_pool(rng: random.Random, size: int = 400) -> list[str]:
    lines = []
    for i in range(size):
        a, b, verb = _ident(rng), _ident(rng), rng.choice(_VERBS)
        lines.append(
            rng.choice(
                (
                    f"def {verb}_{a}_{i}(items, limit={rng.randint(1, 99)}):",
                    f"    return [item for item in items if item.{b} < limit]",
                    f"class {a.title().replace('_', '')}{i}:",
                    f"    {b} = {rng.randint(0, 9999)}",
                    f"    # {verb} the {a} values before the {b} pass",
                    f"    result_{i} = {verb}_{a}(values, {rng.randint(1, 50)})",
                    f"    if {a} > {rng.randint(1, 500)}:",
                    f"        {b} = {a} + {rng.randint(1, 9)}",
                    f'    return f"{{{a}}}: {{{b}}}"',
                    f"import {rng.choice(('math', 'json', 'itertools', 'functools', 'pathlib'))}",
                )
            )
        )
    return lines


def _js_pool(rng: random.Random, size: int = 300) -> list[str]:
    lines = []
    for i in range(size):
        a, b, verb = _ident(rng), _ident(rng), rng.choice(_VERBS)
        lines.append(
            rng.choice(
                (
                    f"function {verb}{a.title().replace('_', '')}{i}(list, limit) {{",
                    f"  return list.filter((entry) => entry.{b} < limit);",
                    f"const {a}_{i} = {rng.randint(0, 9999)};",
                    f"  // {verb} the {a} values before the {b} pass",
                    f"  if ({a} > {rng.randint(1, 500)}) {{ {b} += {rng.randint(1, 9)}; }}",
                    f"module.exports.{a}_{i} = {verb}{a.title().replace('_', '')}{i};",
                )
            )
        )
    return lines


def _md_pool(rng: random.Random, size: int = 300) -> list[str]:
    lines = []
    for i in range(size):
        a, b, verb = _ident(rng), _ident(rng), rng.choice(_VERBS)
        lines.append(
            rng.choice(
                (
                    f"The {a} module can {verb} each {b} before the next step runs ({i}).",
                    f"- {verb} the {a} list, then check the {b} column",
                    f"## Notes on {a} {i}",
                    f"Step {rng.randint(1, 9)}: {verb} the {b} input and record the outcome.",
                    f"Measured {rng.randint(10, 999)} ms for {a} on the reference machine.",
                )
            )
        )
    return lines


@dataclass(frozen=True, slots=True)
class MediumShape:
    """Target shape of a `medium` fixture. `scaled(f)` shrinks every count by `f`
    (used by tests; the real fixture is `MediumShape()`)."""

    commits: int = 3000
    unique_blobs: int = 12000
    blob_bytes: int = 200_000_000
    binaries: int = 40
    tags: int = 30
    branch_commits: int = 100

    def scaled(self, factor: float) -> MediumShape:
        return MediumShape(
            commits=max(60, int(self.commits * factor)),
            unique_blobs=max(240, int(self.unique_blobs * factor)),
            blob_bytes=max(400_000, int(self.blob_bytes * factor)),
            binaries=max(4, int(self.binaries * factor)),
            tags=max(4, int(self.tags * factor)),
            branch_commits=max(6, int(self.branch_commits * factor)),
        )


def _png_noise(rng: random.Random, width: int, height: int) -> bytes:
    image = Image.frombytes("RGB", (width, height), rng.randbytes(width * height * 3))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", compress_level=1)
    return buffer.getvalue()


def _jpeg_noise(rng: random.Random, width: int, height: int) -> bytes:
    image = Image.frombytes("RGB", (width, height), rng.randbytes(width * height * 3))
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=60)
    return buffer.getvalue()


class _TextMaker:
    def __init__(self, rng: random.Random, mean_bytes: int) -> None:
        self.rng = rng
        self.mean = mean_bytes
        self.pools = {
            "py": _python_pool(rng),
            "js": _js_pool(rng),
            "md": _md_pool(rng),
        }
        self.counter = 0

    def blob(self, ext: str) -> bytes:
        self.counter += 1
        pool = self.pools[ext]
        target = int(self.mean * self.rng.uniform(0.2, 1.8))
        lines = max(3, target // 46)
        comment = "//" if ext == "js" else "#"
        header = f"{comment} revision {self.counter}\n"
        return (header + "\n".join(self.rng.choices(pool, k=lines)) + "\n").encode()


def build_history(ctx: FixtureContext, rng: random.Random, shape: MediumShape) -> None:
    """Emit the whole `medium` history onto `ctx`: main plus two merged branches and one
    unmerged branch, tags spread across main, and the binaries."""
    per_binary = 900_000 if shape.blob_bytes >= 100_000_000 else 20_000
    binaries_bytes = shape.binaries * per_binary
    text_blobs = max(1, shape.unique_blobs - shape.binaries)
    maker = _TextMaker(rng, max(200, (shape.blob_bytes - binaries_bytes) // text_blobs))

    branch_plan = {
        "refs/heads/feature/ingest": (shape.commits // 5, True),
        "refs/heads/feature/export": (shape.commits * 1 // 2, True),
        "refs/heads/side/prototype": (shape.commits * 3 // 4, False),
    }
    merge_reserve = 2
    main_commits = shape.commits - len(branch_plan) * shape.branch_commits - merge_reserve
    files_per_commit = max(1, round(shape.unique_blobs / shape.commits))

    binary_at = {int(main_commits * (i + 0.5) / shape.binaries): i for i in range(shape.binaries)}
    tag_at = {int(main_commits * (i + 1) / (shape.tags + 1)): i for i in range(shape.tags)}
    branch_at = {at: (ref, merged) for ref, (at, merged) in branch_plan.items()}

    paths: list[str] = []
    dirs = {
        "py": ["src/core", "src/util", "src/io", "tests"],
        "js": ["web/ui", "web/api"],
        "md": ["docs"],
    }
    exts = ("py", "py", "py", "js", "md")

    created = 0

    def new_path() -> str:
        nonlocal created
        created += 1
        ext = rng.choice(exts)
        directory = rng.choice(dirs[ext])
        return f"{directory}/{_ident(rng)}_{created}.{ext}"

    def text_change(prefix_paths: list[str], taken: dict[str, str | None]) -> tuple[str, str]:
        """A new blob for an existing or new path not already changed in this commit
        (an overwritten blob would be left dangling)."""
        while True:
            if prefix_paths and rng.random() > 0.3:
                path = rng.choice(prefix_paths)
            else:
                path = new_path()
                prefix_paths.append(path)
            if path not in taken:
                break
        return path, ctx.blob(maker.blob(path.rsplit(".", 1)[-1]))

    def branch(ref: str, merged: bool) -> None:
        start = ctx.branch_tip[MAIN]
        touched: dict[str, str | None] = {}
        own_paths: list[str] = []
        namespace = ref.rsplit("/", 1)[-1]
        for i in range(shape.branch_commits):
            changes: dict[str, str | None] = {}
            for _ in range(files_per_commit):
                path, blob = text_change(own_paths, changes)
                changes[path] = blob
            touched.update(changes)
            ctx.commit(
                ref,
                message=f"feat({namespace}): step {i}",
                files=changes,
                from_=start if i == 0 else None,
            )
        if merged:
            ctx.commit(
                MAIN,
                message=f"merge: {namespace}",
                files=touched,
                merges=(ctx.branch_tip[ref],),
            )

    for index in range(main_commits):
        if index in branch_at:
            branch(*branch_at[index])
        changes: dict[str, str | None] = {}
        for _ in range(files_per_commit):
            path, blob = text_change(paths, changes)
            changes[path] = blob
        if index in binary_at:
            n = binary_at[index]
            if n % 5 == 4:
                data = _jpeg_noise(rng, *_image_size(per_binary // 2))
                changes[f"assets/photos/shot_{n:02d}.jpg"] = ctx.blob(data)
            else:
                data = _png_noise(rng, *_image_size(per_binary))
                changes[f"assets/images/figure_{n:02d}.png"] = ctx.blob(data)
        if index % 97 == 96 and len(paths) > 40:
            gone = paths.pop(rng.randrange(len(paths)))
            if gone not in changes:
                changes[gone] = None
        ctx.commit(
            MAIN, message=f"{rng.choice(_VERBS)}: update {len(changes)} files", files=changes
        )
        if index in tag_at:
            n = tag_at[index]
            message = f"Release {n}" if n % 5 == 4 else None
            ctx.request_tag(
                f"v0.{n}.0", ctx.branch_tip[MAIN], message=message, author=ctx.public_identity
            )


def _image_size(byte_target: int) -> tuple[int, int]:
    """Width and height of an RGB noise image whose raw size is about `byte_target`."""
    pixels = max(64, byte_target // 3)
    width = max(8, int((pixels * 6 / 5) ** 0.5))
    return width, max(8, pixels // width)
