"""A scenario repository for the history-preserving export tests.

Every plant-shaped value is assembled at runtime (conventions.md). The history holds
what `--keep-history` has to clean: secrets in a blob, a message and a tag, sensitive
and internal-notes files, an excluded path, a path with a deny term, an image with GPS
metadata, an oversized blob, non-allowlisted identities, flagged trailers and a commit
that carries a signature header. The last commit is clean, so the pre-check passes.
"""

from __future__ import annotations

import random
import subprocess
from dataclasses import dataclass
from pathlib import Path

from go_public.bench import binaries

from ..conftest import PUBLIC_IDENT, git, init_repo
from ..unit import secret_tokens as tok

REG = "100644"
LICENCE = (
    b"MIT License\n\nPermission is hereby granted, free of charge, to any person "
    b"obtaining a copy of this software.\n"
)
EXPORT_AUTHOR = "Pub Lic <pub@example.com>"
DANA = {"name": "Dana Developer", "email": "dana@example.org"}
LEE = {"name": "Lee Reviewer", "email": "lee@example.org"}
COMPANY = "Glo" + "bex"
BIG_BLOB = 3 * 1024 * 1024

CONFIG = (
    f'[identity]\nallow = ["{PUBLIC_IDENT["name"]} <{PUBLIC_IDENT["email"]}>"]\n'
    f'[scan]\njobs = 1\n[deny]\nterms = ["{COMPANY}"]\n'
    '[files]\nwarn_mb = 1\nhigh_mb = 2\n[export]\nexclude = ["docs/private/**"]\n'
)


@dataclass
class Scenario:
    repo: Path
    config: Path
    tokens: dict[str, str]
    commits: dict[str, str]
    big_blob_id: str
    photo_blob_id: str


def _ident_env(
    ident: dict[str, str], date: str, committer: dict[str, str] | None = None
) -> dict[str, str]:
    other = committer or ident
    return {
        "GIT_AUTHOR_NAME": ident["name"],
        "GIT_AUTHOR_EMAIL": ident["email"],
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_NAME": other["name"],
        "GIT_COMMITTER_EMAIL": other["email"],
        "GIT_COMMITTER_DATE": date,
    }


def hash_object(repo: Path, data: bytes, kind: str = "blob") -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "hash-object", "-w", "-t", kind, "--stdin"],
        input=data,
        capture_output=True,
        check=True,
    )
    return proc.stdout.decode().strip()


def add_commit(
    repo: Path,
    files: dict[str, bytes | None],
    message: str,
    *,
    ident: dict[str, str] = PUBLIC_IDENT,
    committer: dict[str, str] | None = None,
    date: str = "2024-01-01T00:00:00+00:00",
    branch: str = "main",
) -> str:
    """Commit on top of `branch`: `files` maps a path to new content, or `None` to
    delete it. Built with plumbing so the working tree is never involved."""
    ref = f"refs/heads/{branch}"
    parent = git(repo, "rev-parse", "--verify", "-q", ref, check=False).decode().strip()
    index = repo / ".git" / "scenario-index.tmp"
    env = {"GIT_INDEX_FILE": str(index)}
    if parent:
        git(repo, "read-tree", parent, env=env)
    for path, content in files.items():
        if content is None:
            git(repo, "update-index", "--remove", path, env=env)
        else:
            oid = hash_object(repo, content)
            git(repo, "update-index", "--add", "--cacheinfo", f"{REG},{oid},{path}", env=env)
    tree = git(repo, "write-tree", env=env).decode().strip()
    index.unlink(missing_ok=True)
    args = ["commit-tree", tree, "-m", message]
    if parent:
        args += ["-p", parent]
    commit = git(repo, *args, env=_ident_env(ident, date, committer)).decode().strip()
    git(repo, "update-ref", ref, commit)
    return commit


def add_signed_commit(repo: Path, message: str, *, branch: str = "main") -> str:
    """A commit whose object carries a `gpgsig` header (not a real signature)."""
    ref = f"refs/heads/{branch}"
    parent = git(repo, "rev-parse", ref).decode().strip()
    tree = git(repo, "rev-parse", f"{parent}^{{tree}}").decode().strip()
    ident = f"{PUBLIC_IDENT['name']} <{PUBLIC_IDENT['email']}> 1704153600 +0000"
    sig = (
        "gpgsig -----BEGIN PGP SIGNATURE-----\n \n " + "x" * 20 + "\n -----END PGP SIGNATURE-----\n"
    )
    raw = f"tree {tree}\nparent {parent}\nauthor {ident}\ncommitter {ident}\n{sig}\n{message}\n"
    commit = hash_object(repo, raw.encode(), "commit")
    git(repo, "update-ref", ref, commit)
    return commit


def build(tmp_path: Path, *, branch: str = "main", seed: int = 1) -> Scenario:
    rng = random.Random(seed)
    tokens = {
        "blob": tok.aws_access_key(rng),
        "message": tok.github_pat_classic(rng),
        "tag": tok.stripe_secret_key(rng),
        "utf16": tok.google_api_key(rng),
    }
    repo = init_repo(tmp_path / "src")
    git(repo, "symbolic-ref", "HEAD", f"refs/heads/{branch}")
    photo = binaries.jpeg_with_gps(12.5, 45.25)
    big = random.Random(99).randbytes(BIG_BLOB)
    utf16 = (f"key = {tokens['utf16']}\n").encode("utf-16")

    c1 = add_commit(
        repo,
        {
            "LICENSE": LICENCE,
            "README.md": b"# Demo\n",
            "src/app.py": b"print('hi')\n",
            ".env": b"MODE=dev\n",
            "notes/plan.md": b"remember the milk\n",
            "secret.txt": f"aws = {tokens['blob']}\n".encode(),
            f"docs/{COMPANY.lower()}-design.md": b"design\n",
            "docs/private/x.md": b"private\n",
            "img/photo.jpg": photo,
            "big.bin": big,
            "wide.txt": utf16,
        },
        f"feat: initial import for {COMPANY}\n\nnote {tokens['message']} kept here\n\n"
        "Change-Id: I0123456789\n"
        f"Signed-off-by: {DANA['name']} <{DANA['email']}>\n"
        f"Reviewed-by: {LEE['name']} <{LEE['email']}>\n",
        ident=DANA,
        date="2024-01-10T10:00:00+02:00",
        branch=branch,
    )
    c2 = add_commit(
        repo,
        {
            ".env": None,
            "notes/plan.md": None,
            "secret.txt": None,
            f"docs/{COMPANY.lower()}-design.md": None,
            "docs/private/x.md": None,
            "img/photo.jpg": None,
            "big.bin": None,
            "wide.txt": None,
        },
        "chore: remove what should not be public",
        ident=DANA,
        committer=LEE,
        date="2024-02-01T10:00:00+00:00",
        branch=branch,
    )
    c3 = add_commit(
        repo,
        {"README.md": b"# Demo\n\nRun `python src/app.py`.\n"},
        "docs: usage",
        ident=LEE,
        date="2024-03-01T10:00:00+00:00",
        branch=branch,
    )
    c4 = add_signed_commit(repo, "chore: signed release commit", branch=branch)

    tagger = _ident_env(DANA, "2024-02-01T12:00:00+00:00")
    git(repo, "tag", "-a", "v1", "-m", f"release one {tokens['tag']}", c2, env=tagger)
    git(repo, "tag", f"{COMPANY.lower()}-1.0", c1)
    git(repo, "tag", "v0.1", c1)
    git(repo, "reset", "-q", "--hard")
    return Scenario(
        repo=repo,
        config=repo.parent / "go-public.toml",
        tokens=tokens,
        commits={"c1": c1, "c2": c2, "c3": c3, "c4": c4},
        big_blob_id=git(repo, "rev-parse", f"{c1}:big.bin").decode().strip(),
        photo_blob_id=git(repo, "rev-parse", f"{c1}:img/photo.jpg").decode().strip(),
    )


def write_config(scenario: Scenario, extra: str = "") -> Path:
    scenario.config.write_text(CONFIG + extra)
    return scenario.config
