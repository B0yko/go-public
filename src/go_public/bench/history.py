"""Extra realistic history for `small` fixtures: more commits on main, edits and
deletions of ordinary files, merged and unmerged branches, lightweight and annotated
tags. Everything here is filler: no finding is expected from any of it (a
`--no-plants` fixture must scan to zero findings).
"""

from __future__ import annotations

import random

from go_public.bench import filler
from go_public.bench.plants import FixtureContext, Identity

MAIN = "refs/heads/main"


def module_bytes(rng: random.Random, path: str, revision: int) -> bytes:
    """A python module whose content changes with every revision (a unique blob)."""
    body = filler.python_module(rng, path.rsplit("/", 1)[-1])
    return body + f"\nREVISION = {revision}\n".encode()


def small_history(
    ctx: FixtureContext, rng: random.Random, *, colleagues: tuple[Identity, ...]
) -> None:
    """About 45 more commits: 12 that add module files, 20 edits, 3 deletions, two
    merged feature branches, one unmerged spike branch and five tags. Authors come
    from `colleagues` when given (their identity findings are covered by the identity
    plants), else the public identity."""
    revisions: dict[str, int] = {}

    def who() -> Identity | None:
        return rng.choice(colleagues) if colleagues else None

    def write(ref: str, path: str, message: str) -> str:
        revisions[path] = revisions.get(path, 0) + 1
        blob = ctx.blob(module_bytes(rng, path, revisions[path]))
        return ctx.commit(ref, message=message, files={path: blob}, author=who())

    for index in range(12):
        name = f"src/pkg/mod_{index:02d}.py" if index % 2 == 0 else f"tests/test_mod_{index:02d}.py"
        write(MAIN, name, f"feat: add {name}")
        if index == 3:
            ctx.request_tag(
                "v0.2.0", ctx.branch_tip[MAIN], message=None, author=ctx.public_identity
            )

    # A merged feature branch with files of its own.
    parser_ref = "refs/heads/feature/parser"
    parser_files: dict[str, str] = {}
    write_first = True
    for i in range(4):
        path = f"src/parser/part_{i}.py"
        revisions[path] = 1
        blob = ctx.blob(module_bytes(rng, path, 1))
        parser_files[path] = blob
        ctx.commit(
            parser_ref,
            message=f"feat(parser): part {i}",
            files={path: blob},
            author=who(),
            from_=ctx.branch_tip[MAIN] if write_first else None,
        )
        write_first = False
    ctx.commit(
        MAIN,
        message="merge: parser",
        files=dict(parser_files),
        merges=(ctx.branch_tip[parser_ref],),
    )

    editable = [p for p in sorted(revisions) if not p.startswith("src/parser/")]
    for index in range(20):
        path = rng.choice(editable)
        write(MAIN, path, f"fix: adjust {path.rsplit('/', 1)[-1]}")
        if index == 9:
            ctx.request_tag(
                "v0.3.0", ctx.branch_tip[MAIN], message=None, author=ctx.public_identity
            )
        if index == 14:
            ctx.request_tag(
                "v0.4.0", ctx.branch_tip[MAIN], message="Release 0.4.0", author=ctx.public_identity
            )

    for path in rng.sample([p for p in editable if p.startswith("tests/")], k=3):
        ctx.commit(MAIN, message=f"chore: drop {path}", files={path: None})

    docs_blob = ctx.blob(filler.markdown_notes(rng, "guide"))
    docs_tip = ctx.commit(
        "refs/heads/feature/docs",
        message="docs: add guide",
        files={"docs/guide.md": docs_blob},
        from_=ctx.branch_tip[MAIN],
    )
    ctx.commit(MAIN, message="merge: docs", files={"docs/guide.md": docs_blob}, merges=(docs_tip,))

    spike = "refs/heads/side/spike"
    main_tip = ctx.branch_tip[MAIN]
    for i in range(3):
        blob = ctx.blob(module_bytes(rng, "spike.py", i + 1))
        ctx.commit(
            spike,
            message=f"wip: spike {i}",
            files={f"spike/try_{i}.py": blob},
            from_=main_tip if i == 0 else None,
        )
    ctx.request_tag(
        "v1.0.0-rc1",
        ctx.branch_tip[MAIN],
        message="Release candidate 1",
        author=ctx.public_identity,
    )
