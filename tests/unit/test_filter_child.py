"""`export/_filter_child.py`: the rewrite callbacks, driven with plain stand-ins."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest

from go_public.export import _filter_child as child

REMOVED = "***REMOVED***"


def _spec(**overrides: object) -> dict[str, object]:
    spec: dict[str, object] = {
        "version": child.SPEC_VERSION,
        "identity": {"name": "Pub Lic", "email": "pub@example.com"},
        "mailmap": None,
        "replacement": REMOVED,
        "blob_values": {},
        "commit_values": {},
        "tag_values": {},
        "drop_paths": [],
        "flagged_trailers": ["Change-Id"],
        "strip_metadata": True,
        "max_blob_bytes": None,
    }
    spec.update(overrides)
    return spec


@dataclass
class FakeBlob:
    data: bytes
    original_id: bytes = b"b" * 40
    skipped: bool = False

    def skip(self) -> None:
        self.skipped = True


@dataclass
class FakeCommit:
    message: bytes
    original_id: bytes = b"c" * 40
    author_name: bytes = b"A"
    author_email: bytes = b"a@example.org"
    committer_name: bytes = b"C"
    committer_email: bytes = b"c@example.org"


@dataclass
class FakeTag:
    message: bytes
    original_id: bytes = b"t" * 40
    tagger_name: bytes = b"T"
    tagger_email: bytes = b"t@example.org"
    extras: list[str] = field(default_factory=list)


def test_replace_values_is_longest_first_and_literal() -> None:
    data = b"key=abcdef and abc, a.c"
    out = child.replace_values(data, ["abc", "abcdef", "a.c"], REMOVED)
    assert out == f"key={REMOVED} and {REMOVED}, {REMOVED}".encode()


def test_replace_values_keeps_utf16_encoding_and_bom() -> None:
    data = "token = s3cr3t-value\n".encode("utf-16")
    out = child.replace_values(data, ["s3cr3t-value"], REMOVED)
    assert out[:2] == data[:2]
    assert out.decode("utf-16") == f"token = {REMOVED}\n"
    be = b"\xfe\xff" + "x s3cr3t-value".encode("utf-16-be")
    assert child.replace_values(be, ["s3cr3t-value"], REMOVED)[2:].decode("utf-16-be") == (
        f"x {REMOVED}"
    )


def test_replace_values_without_values_returns_the_same_bytes() -> None:
    data = b"nothing here"
    assert child.replace_values(data, [], REMOVED) is data
    assert child.replace_values(data, [""], REMOVED) is data


def test_blob_values_apply_only_to_the_blob_that_carried_them() -> None:
    rewriter = child.Rewriter(_spec(blob_values={"b" * 40: ["s3cr3t"]}))
    hit = FakeBlob(b"a s3cr3t here")
    other = FakeBlob(b"a s3cr3t here", original_id=b"o" * 40)

    rewriter.blob(hit)
    rewriter.blob(other)

    assert hit.data == f"a {REMOVED} here".encode()
    assert other.data == b"a s3cr3t here"
    assert rewriter.stats.blobs_replaced == 1


def test_blobs_at_or_above_the_limit_are_skipped() -> None:
    rewriter = child.Rewriter(_spec(max_blob_bytes=10))
    big, small = FakeBlob(b"x" * 10), FakeBlob(b"x" * 9)

    rewriter.blob(big)
    rewriter.blob(small)

    assert big.skipped and not small.skipped
    assert rewriter.stats.blobs_dropped == 1


def test_strip_metadata_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bytes] = []

    def fake_strip(data: bytes) -> bytes:
        calls.append(data)
        return b"stripped"

    monkeypatch.setattr(child, "strip_bytes", fake_strip)
    on = FakeBlob(b"original")
    child.Rewriter(_spec()).blob(on)
    off = FakeBlob(b"original")
    child.Rewriter(_spec(strip_metadata=False)).blob(off)

    assert on.data == b"stripped" and off.data == b"original"
    assert calls == [b"original"]


def test_commits_get_the_export_identity_and_lose_flagged_trailers() -> None:
    rewriter = child.Rewriter(_spec(commit_values={"c" * 40: ["s3cr3t"]}))
    commit = FakeCommit(b"feat: x s3cr3t\n\nbody\n\nChange-Id: I1\nFixes: 2\n")

    rewriter.commit(commit)

    assert commit.message == f"feat: x {REMOVED}\n\nbody\n\nFixes: 2\n".encode()
    assert (commit.author_name, commit.author_email) == (b"Pub Lic", b"pub@example.com")
    assert (commit.committer_name, commit.committer_email) == (b"Pub Lic", b"pub@example.com")


def test_without_an_identity_the_names_are_left_to_the_mailmap() -> None:
    rewriter = child.Rewriter(_spec(identity=None))
    commit, tag = FakeCommit(b"m\n"), FakeTag(b"t\n")

    rewriter.commit(commit)
    rewriter.tag(tag)

    assert commit.author_name == b"A" and tag.tagger_name == b"T"


def test_tags_get_the_export_identity_and_their_values_replaced() -> None:
    rewriter = child.Rewriter(_spec(tag_values={"t" * 40: ["s3cr3t"]}))
    tag = FakeTag(b"release s3cr3t\n")

    rewriter.tag(tag)

    assert tag.message == f"release {REMOVED}\n".encode()
    assert (tag.tagger_name, tag.tagger_email) == (b"Pub Lic", b"pub@example.com")


def test_messages_with_undecodable_bytes_survive() -> None:
    rewriter = child.Rewriter(_spec(commit_values={"c" * 40: ["s3cr3t"]}))
    commit = FakeCommit(b"caf\xe9 s3cr3t\n")

    rewriter.commit(commit)

    assert commit.message == b"caf\xe9 " + REMOVED.encode() + b"\n"


def test_drop_paths_remove_exact_paths_only() -> None:
    rewriter = child.Rewriter(_spec(drop_paths=[".env", "docs/x.md"]))

    assert rewriter.filename(b".env") is None
    assert rewriter.filename(b"docs/x.md") is None
    assert rewriter.filename(b"docs/x.md.bak") == b"docs/x.md.bak"
    assert rewriter.filename(b"sub/.env") == b"sub/.env"
    assert rewriter.stats.paths_dropped == {".env", "docs/x.md"}


def test_stats_are_json() -> None:
    stats = child.Stats(blobs_dropped=1)
    assert json.loads(stats.as_json())["blobs_dropped"] == 1


def test_parse_spec_rejects_wrong_versions_and_missing_keys() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        child.parse_spec(json.dumps({"version": 99}))
    with pytest.raises(ValueError, match="lacks"):
        child.parse_spec(json.dumps({"version": child.SPEC_VERSION}))
    with pytest.raises(ValueError, match="unsupported"):
        child.parse_spec("[]")
    assert child.parse_spec(json.dumps(_spec()))["replacement"] == REMOVED


def test_main_reports_a_bad_specification_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io
    import sys

    monkeypatch.setattr(sys, "stdin", io.StringIO("not json"))

    assert child.main() == 2
    assert "bad specification" in capsys.readouterr().err
