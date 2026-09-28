"""Raw commit/tag object parsing and a `cat-file --batch` reader.

Parsing raw objects ourselves (rather than `git log --pretty=...`) keeps headers,
encoding and timezones exact, and lets a single `cat-file --batch` pass serve both
commit metadata and blob content.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from go_public.git.runner import GitRunner

_IDENT_RE = re.compile(r"^(.*) <([^>]*)> (\d+) ([+-]\d{4})$")
_TRAILER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)$")


def blob_id(content: bytes) -> str:
    """The blob object id git would assign this content, without asking git:
    `sha1(f"blob {len(content)}\\0" + data)`. Used wherever a blob id is needed for
    content we already hold in memory and never wrote to any repository (fixture
    plants; `go-public redact`'s fingerprint recompute against a working-tree file)."""
    header = f"blob {len(content)}\0".encode()
    return hashlib.sha1(header + content).hexdigest()  # noqa: S324 (git's own object hash)


@dataclass(frozen=True)
class Ident:
    name: str
    email: str
    timestamp: int
    tz: str

    @property
    def display(self) -> str:
        return f"{self.name} <{self.email}>"


@dataclass(frozen=True)
class Trailer:
    key: str
    value: str
    line: str


@dataclass(frozen=True)
class CommitObj:
    oid: str
    tree: str
    parents: list[str]
    author: Ident
    committer: Ident
    encoding: str | None
    gpgsig: bool
    message: str
    raw_headers: list[tuple[str, bytes]] = field(default_factory=list)


@dataclass(frozen=True)
class TagObj:
    oid: str
    object: str
    type: str
    tag: str
    tagger: Ident | None
    message: str


def _decode(raw: bytes, encoding: str | None) -> str:
    for enc in filter(None, (encoding, "utf-8")):
        try:
            return raw.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", errors="surrogateescape")


def _split_headers_message(raw: bytes) -> tuple[bytes, bytes]:
    """Split a raw commit/tag object on the first genuinely blank line.

    A continuation line inside a multi-line header (e.g. `gpgsig`) always starts
    with a space, so it is never mistaken for the blank line that ends the headers.
    """
    lines = raw.split(b"\n")
    for i, line in enumerate(lines):
        if line == b"":
            headers = b"\n".join(lines[:i])
            message = b"\n".join(lines[i + 1 :])
            return headers, message
    return raw, b""


def _parse_headers(headers: bytes) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    for line in headers.split(b"\n"):
        if not line:
            continue
        if line.startswith(b" ") and result:
            key, value = result[-1]
            result[-1] = (key, value + b"\n" + line[1:])
            continue
        key_b, _, value = line.partition(b" ")
        result.append((key_b.decode("ascii", "replace"), value))
    return result


def _header_value(headers: list[tuple[str, bytes]], key: str) -> bytes | None:
    for k, v in headers:
        if k == key:
            return v
    return None


def _header_values(headers: list[tuple[str, bytes]], key: str) -> list[bytes]:
    return [v for k, v in headers if k == key]


def _parse_ident(raw: bytes, encoding: str | None) -> Ident:
    text = _decode(raw, encoding)
    match = _IDENT_RE.match(text)
    if not match:
        # Malformed identity line; keep the raw text visible rather than crashing.
        return Ident(name=text, email="", timestamp=0, tz="+0000")
    name, email, ts, tz = match.groups()
    return Ident(name=name, email=email, timestamp=int(ts), tz=tz)


def parse_commit(oid: str, raw: bytes) -> CommitObj:
    """Parse a raw `commit` object as returned by `git cat-file --batch`."""
    headers_b, message_b = _split_headers_message(raw)
    headers = _parse_headers(headers_b)
    encoding_b = _header_value(headers, "encoding")
    encoding = encoding_b.decode("ascii", "replace") if encoding_b is not None else None
    tree_b = _header_value(headers, "tree") or b""
    author_b = _header_value(headers, "author") or b""
    committer_b = _header_value(headers, "committer") or b""
    return CommitObj(
        oid=oid,
        tree=tree_b.decode("ascii", "replace"),
        parents=[p.decode("ascii", "replace") for p in _header_values(headers, "parent")],
        author=_parse_ident(author_b, encoding),
        committer=_parse_ident(committer_b, encoding),
        encoding=encoding,
        gpgsig=_header_value(headers, "gpgsig") is not None,
        message=_decode(message_b, encoding),
        raw_headers=headers,
    )


def parse_tag(oid: str, raw: bytes) -> TagObj:
    """Parse a raw annotated `tag` object as returned by `git cat-file --batch`."""
    headers_b, message_b = _split_headers_message(raw)
    headers = _parse_headers(headers_b)
    tagger_b = _header_value(headers, "tagger")
    return TagObj(
        oid=oid,
        object=(_header_value(headers, "object") or b"").decode("ascii", "replace"),
        type=(_header_value(headers, "type") or b"").decode("ascii", "replace"),
        tag=(_header_value(headers, "tag") or b"").decode("ascii", "replace"),
        tagger=_parse_ident(tagger_b, None) if tagger_b is not None else None,
        message=_decode(message_b, None),
    )


def _split_paragraphs(message: str) -> list[str]:
    stripped = message.strip("\n")
    if not stripped:
        return []
    blocks = re.split(r"\n[ \t]*\n", stripped)
    return [b for b in blocks if b.strip()]


def parse_trailers(message: str) -> list[Trailer]:
    """Return the trailers in the message's last paragraph (approximating git's rules).

    The whole last paragraph must look like trailers (`Key: value` lines, optionally
    folded onto an indented continuation line); otherwise there are none.
    """
    paragraphs = _split_paragraphs(message)
    if len(paragraphs) < 2:
        # A lone paragraph is the subject/description, never a trailer block: a
        # conventional-commit subject like "feat: thing" must not be misread as one.
        return []
    trailers: list[Trailer] = []
    for line in paragraphs[-1].splitlines():
        match = _TRAILER_RE.match(line)
        if match is None:
            if trailers and line.startswith((" ", "\t")):
                prev = trailers[-1]
                trailers[-1] = Trailer(
                    key=prev.key, value=f"{prev.value} {line.strip()}", line=prev.line
                )
                continue
            return []
        trailers.append(Trailer(key=match.group(1), value=match.group(2).strip(), line=line))
    return trailers


class CatFileBatch:
    """A request/response wrapper over `git cat-file --batch[-check]`."""

    def __init__(self, runner: GitRunner, *, check_only: bool = False) -> None:
        self._runner = runner
        self._check_only = check_only
        self._proc: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> CatFileBatch:
        args = ["cat-file", "--batch-check" if self._check_only else "--batch"]
        self._proc = self._runner.popen(args)
        return self

    def __exit__(self, *exc_info: object) -> None:
        proc = self._proc
        if proc is None:
            return
        if proc.stdin is not None:
            proc.stdin.close()
        if proc.stdout is not None:
            proc.stdout.close()
        proc.wait()

    def get(self, oid: str) -> tuple[str, bytes] | None:
        """Return `(type, content)` for `oid`, or `None` when git reports it missing.

        Only valid when the batch was opened without `check_only`.
        """
        assert not self._check_only, "get() needs a --batch reader, not --batch-check"
        proc = self._proc
        assert proc is not None and proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(oid.encode() + b"\n")
        proc.stdin.flush()
        header = proc.stdout.readline().split()
        if len(header) < 2:
            raise RuntimeError(f"unexpected cat-file output: {header!r}")
        if header[1] == b"missing":
            return None
        size = int(header[2])
        data = proc.stdout.read(size)
        proc.stdout.read(1)  # the trailing newline after the object body
        return header[1].decode(), data

    def check(self, oid: str) -> tuple[str, int] | None:
        """Return `(type, size)` for `oid` via `--batch-check`, or `None` if missing."""
        assert self._check_only, "check() needs a --batch-check reader"
        proc = self._proc
        assert proc is not None and proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(oid.encode() + b"\n")
        proc.stdin.flush()
        header = proc.stdout.readline().split()
        if len(header) < 2:
            raise RuntimeError(f"unexpected cat-file output: {header!r}")
        if header[1] == b"missing":
            return None
        return header[1].decode(), int(header[2])
