"""Raw commit/tag parsing, trailer extraction, and the cat-file --batch reader."""

from __future__ import annotations

from pathlib import Path

from go_public.git.objects import CatFileBatch, parse_commit, parse_tag, parse_trailers
from go_public.git.runner import GitRunner

from ..conftest import commit_file, git, init_repo

ZERO_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def test_parse_commit_basic_fields() -> None:
    raw = (
        f"tree {ZERO_TREE}\n"
        "parent aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "author Pat Public <pat@example.com> 1700000000 +0000\n"
        "committer Pat Public <pat@example.com> 1700000000 +0000\n"
        "\n"
        "feat: a commit\n"
    ).encode()
    commit = parse_commit("cccc", raw)
    assert commit.oid == "cccc"
    assert commit.tree == ZERO_TREE
    assert commit.parents == ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    assert commit.author.name == "Pat Public"
    assert commit.author.email == "pat@example.com"
    assert commit.author.timestamp == 1700000000
    assert commit.author.tz == "+0000"
    assert commit.author.display == "Pat Public <pat@example.com>"
    assert commit.encoding is None
    assert commit.gpgsig is False
    assert commit.message == "feat: a commit\n"


def test_parse_commit_root_has_no_parents() -> None:
    raw = (
        f"tree {ZERO_TREE}\n"
        "author Pat Public <pat@example.com> 1700000000 +0000\n"
        "committer Pat Public <pat@example.com> 1700000000 +0000\n"
        "\n"
        "root\n"
    ).encode()
    assert parse_commit("r", raw).parents == []


def test_parse_commit_merge_has_two_parents() -> None:
    raw = (
        f"tree {ZERO_TREE}\n"
        "parent aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "parent bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "author Pat Public <pat@example.com> 1700000000 +0000\n"
        "committer Pat Public <pat@example.com> 1700000000 +0000\n"
        "\n"
        "merge\n"
    ).encode()
    commit = parse_commit("m", raw)
    assert commit.parents == [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ]


def test_parse_commit_encoding_header_decodes_message_and_keeps_tz() -> None:
    message_bytes = "café\n".encode("latin-1")
    raw = (
        f"tree {ZERO_TREE}\n"
        "author Pat Public <pat@example.com> 1700000000 +0100\n"
        "committer Pat Public <pat@example.com> 1700000000 +0100\n"
        "encoding ISO-8859-1\n"
        "\n"
    ).encode() + message_bytes
    commit = parse_commit("e", raw)
    assert commit.encoding == "ISO-8859-1"
    assert commit.message == "café\n"
    assert commit.author.tz == "+0100"


def test_parse_commit_multiline_gpgsig_header() -> None:
    raw = (
        f"tree {ZERO_TREE}\n"
        "author Pat Public <pat@example.com> 1700000000 +0000\n"
        "committer Pat Public <pat@example.com> 1700000000 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n"
        " \n"
        " iQEzBAABCAAdFiEE\n"
        " -----END PGP SIGNATURE-----\n"
        "\n"
        "signed\n"
    ).encode()
    commit = parse_commit("g", raw)
    assert commit.gpgsig is True
    assert commit.message == "signed\n"
    gpgsig_value = next(v for k, v in commit.raw_headers if k == "gpgsig")
    assert b"BEGIN PGP SIGNATURE" in gpgsig_value
    assert b"iQEzBAABCAAdFiEE" in gpgsig_value


def test_parse_tag_basic_fields() -> None:
    raw = (
        b"object cccccccccccccccccccccccccccccccccccccccc\n"
        b"type commit\n"
        b"tag v1.0\n"
        b"tagger Pat Public <pat@example.com> 1700000000 +0000\n"
        b"\n"
        b"release\n"
    )
    tag = parse_tag("t", raw)
    assert tag.object == "cccccccccccccccccccccccccccccccccccccccc"
    assert tag.type == "commit"
    assert tag.tag == "v1.0"
    assert tag.tagger is not None
    assert tag.tagger.email == "pat@example.com"
    assert tag.message == "release\n"


def test_parse_tag_lightweight_ref_never_reaches_here() -> None:
    # Sanity: a tag with no tagger line (unusual but git permits it).
    raw = b"object cccccccccccccccccccccccccccccccccccccccc\ntype commit\ntag v1.0\n\nrelease\n"
    tag = parse_tag("t", raw)
    assert tag.tagger is None


def test_parse_trailers_simple() -> None:
    message = "feat: thing\n\nBody text.\n\nSigned-off-by: Pat Public <pat@example.com>\n"
    trailers = parse_trailers(message)
    assert len(trailers) == 1
    assert trailers[0].key == "Signed-off-by"
    assert trailers[0].value == "Pat Public <pat@example.com>"


def test_parse_trailers_multiple() -> None:
    message = "feat: thing\n\nCo-authored-by: A <a@example.com>\nReviewed-by: B <b@example.com>\n"
    trailers = parse_trailers(message)
    assert [t.key for t in trailers] == ["Co-authored-by", "Reviewed-by"]


def test_parse_trailers_none_when_last_paragraph_is_prose() -> None:
    message = "feat: thing\n\nJust a sentence, no trailers here.\n"
    assert parse_trailers(message) == []


def test_parse_trailers_none_for_single_paragraph_message() -> None:
    assert parse_trailers("feat: thing\n") == []


def test_parse_trailers_folded_continuation() -> None:
    message = "feat: thing\n\nChange-Id: abcdef\n  more detail on the same trailer\n"
    trailers = parse_trailers(message)
    assert len(trailers) == 1
    assert trailers[0].key == "Change-Id"
    assert "more detail" in trailers[0].value


def test_cat_file_batch_reads_commit_and_reports_missing(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    oid = commit_file(repo, "a.txt", "hello\n", "feat: initial")
    runner = GitRunner(repo, role="source")
    with CatFileBatch(runner) as batch:
        result = batch.get(oid)
        assert result is not None
        obj_type, data = result
        assert obj_type == "commit"
        assert b"feat: initial" in data
        assert batch.get("0" * 40) is None


def test_cat_file_batch_check_reports_blob_size(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hello\n", "feat: initial")
    blob_oid = git(repo, "rev-parse", "HEAD:a.txt").decode().strip()
    runner = GitRunner(repo, role="source")
    with CatFileBatch(runner, check_only=True) as batch:
        result = batch.check(blob_oid)
        assert result == ("blob", 6)
