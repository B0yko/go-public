"""The git-filter-repo child process of the history-preserving export (ADR 0007).

Started by `export/history.py` as `python -P -m go_public.export._filter_child` with the
fresh clone as its working directory. The rewrite specification arrives as one JSON
document on stdin, so the literal values to remove never touch argv or disk. The
module runs `git_filter_repo.RepoFilter` as a library with these callbacks:

- blobs: dropped at or above the size limit, stripped of binary metadata, and the
  literal values behind findings in that very blob replaced;
- commits: the export identity for author and committer (unless a mailmap is given),
  the configured trailers removed, the literal values behind message findings replaced;
- tags: the same for the tagger and the tag message;
- file names: every path on the drop list is removed from every commit.

Values are keyed by the source object id (`original_id`), so a value that is
allowlisted in one place is left alone there. This module is the only place outside
`GitRunner` that reaches git (through git-filter-repo's own `git` calls).
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any

from go_public.detect.commit_meta import strip_trailers
from go_public.export.strip import strip_bytes

SPEC_VERSION = 1
_UTF16_BOMS = {b"\xff\xfe": "utf-16-le", b"\xfe\xff": "utf-16-be"}
STATS_PREFIX = "GO_PUBLIC_STATS "


def replace_values(data: bytes, values: list[str], replacement: str) -> bytes:
    """`data` with every literal occurrence of each value replaced, longest value first
    so a value that contains another is replaced as a whole. UTF-16 files (with a BOM)
    are decoded, replaced and encoded back with the same BOM."""
    ordered = sorted({v for v in values if v}, key=len, reverse=True)
    if not ordered:
        return data
    codec = _UTF16_BOMS.get(data[:2])
    if codec is not None:
        try:
            text = data[2:].decode(codec)
        except UnicodeDecodeError:
            return data
        for value in ordered:
            text = text.replace(value, replacement)
        return data[:2] + text.encode(codec)
    for value in ordered:
        data = data.replace(value.encode("utf-8"), replacement.encode("utf-8"))
    return data


def replace_text(text: str, values: list[str], replacement: str) -> str:
    for value in sorted({v for v in values if v}, key=len, reverse=True):
        text = text.replace(value, replacement)
    return text


@dataclass(slots=True)
class Stats:
    blobs_dropped: int = 0
    blobs_stripped: int = 0
    blobs_replaced: int = 0
    commits_rewritten: int = 0
    tags_rewritten: int = 0
    paths_dropped: set[str] = field(default_factory=set)

    def as_json(self) -> str:
        return json.dumps(
            {
                "blobs_dropped": self.blobs_dropped,
                "blobs_stripped": self.blobs_stripped,
                "blobs_replaced": self.blobs_replaced,
                "commits_rewritten": self.commits_rewritten,
                "tags_rewritten": self.tags_rewritten,
                "paths_dropped": len(self.paths_dropped),
            }
        )


class Rewriter:
    """The callbacks. Operates on objects with git-filter-repo's attribute names, so
    tests drive it with plain stand-ins."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self.replacement: str = spec["replacement"]
        self.blob_values: dict[str, list[str]] = spec["blob_values"]
        self.commit_values: dict[str, list[str]] = spec["commit_values"]
        self.tag_values: dict[str, list[str]] = spec["tag_values"]
        self.drop_paths: frozenset[str] = frozenset(spec["drop_paths"])
        self.flagged_trailers: list[str] = spec["flagged_trailers"]
        self.strip_metadata: bool = spec["strip_metadata"]
        self.max_blob_bytes: int | None = spec["max_blob_bytes"]
        identity = spec["identity"]
        self.name: bytes | None = identity["name"].encode() if identity else None
        self.email: bytes | None = identity["email"].encode() if identity else None
        self.stats = Stats()

    # -- git-filter-repo callbacks -------------------------------------------------

    def blob(self, blob: Any, _metadata: Any = None) -> None:
        data: bytes = blob.data
        if self.max_blob_bytes is not None and len(data) >= self.max_blob_bytes:
            blob.skip()
            self.stats.blobs_dropped += 1
            return
        updated = data
        if self.strip_metadata:
            try:
                updated = strip_bytes(updated)
            except Exception as exc:  # noqa: BLE001 - an unstripped blob must not ship
                raise RuntimeError(
                    f"cannot strip metadata from blob {_oid(blob)}: {exc} "
                    "(--no-strip keeps such files unchanged)"
                ) from exc
            if updated != data:
                self.stats.blobs_stripped += 1
        values = self.blob_values.get(_oid(blob))
        if values:
            replaced = replace_values(updated, values, self.replacement)
            if replaced != updated:
                self.stats.blobs_replaced += 1
            updated = replaced
        if updated != data:
            blob.data = updated

    def commit(self, commit: Any, _metadata: Any = None) -> None:
        if self.name is not None and self.email is not None:
            commit.author_name = commit.committer_name = self.name
            commit.author_email = commit.committer_email = self.email
        commit.message = self._message(commit.message, self.commit_values.get(_oid(commit)))
        self.stats.commits_rewritten += 1

    def tag(self, tag: Any, _metadata: Any = None) -> None:
        if self.name is not None and self.email is not None:
            tag.tagger_name = self.name
            tag.tagger_email = self.email
        tag.message = self._message(tag.message, self.tag_values.get(_oid(tag)))
        self.stats.tags_rewritten += 1

    def filename(self, name: bytes) -> bytes | None:
        path = name.decode("utf-8", "replace")
        if path in self.drop_paths:
            self.stats.paths_dropped.add(path)
            return None
        return name

    # -- helpers ---------------------------------------------------------------------

    def _message(self, message: bytes, values: list[str] | None) -> bytes:
        text = message.decode("utf-8", "surrogateescape")
        text = strip_trailers(text, self.flagged_trailers)
        if values:
            text = replace_text(text, values, self.replacement)
        return text.encode("utf-8", "surrogateescape")


def _oid(obj: Any) -> str:
    original = getattr(obj, "original_id", None)
    if original is None:
        return ""
    return original.decode() if isinstance(original, bytes) else str(original)


_REQUIRED = (
    "version",
    "identity",
    "mailmap",
    "replacement",
    "blob_values",
    "commit_values",
    "tag_values",
    "drop_paths",
    "flagged_trailers",
    "strip_metadata",
    "max_blob_bytes",
)


def parse_spec(raw: str) -> dict[str, Any]:
    spec = json.loads(raw)
    if not isinstance(spec, dict) or spec.get("version") != SPEC_VERSION:
        raise ValueError("unsupported specification")
    missing = [key for key in _REQUIRED if key not in spec]
    if missing:
        raise ValueError(f"specification lacks: {', '.join(missing)}")
    return spec


def run_filter(spec: dict[str, Any]) -> Stats:
    import git_filter_repo as fr

    rewriter = Rewriter(spec)
    argv = ["--force", "--quiet"]
    if spec["mailmap"]:
        argv += ["--mailmap", spec["mailmap"]]
        rewriter.name = rewriter.email = None
    options = fr.FilteringOptions.parse_args(argv, error_on_empty=False)
    fr.RepoFilter(
        options,
        blob_callback=rewriter.blob,
        commit_callback=rewriter.commit,
        tag_callback=rewriter.tag,
        filename_callback=rewriter.filename,
    ).run()
    return rewriter.stats


def main() -> int:
    try:
        spec = parse_spec(sys.stdin.read())
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"go-public filter child: bad specification: {exc}", file=sys.stderr)
        return 2
    # git-filter-repo starts git children; none of them may read the specification.
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    try:
        stats = run_filter(spec)
    except SystemExit as exc:
        print(f"go-public filter child: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - report the failure class, never the data
        print(f"go-public filter child: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(STATS_PREFIX + stats.as_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
