"""`detect/commit_meta.py`: identity allow-matching, trailers, timezone offsets."""

from __future__ import annotations

from go_public.detect.commit_meta import (
    collect_identities,
    collect_timezone_offsets,
    collect_trailers,
    group_non_allowed_identities,
    is_identity_allowed,
    trailer_severity,
)
from go_public.git.objects import CommitObj, Ident


def _commit(oid: str, *, author: Ident, committer: Ident | None = None, message: str) -> CommitObj:
    return CommitObj(
        oid=oid,
        tree="0" * 40,
        parents=[],
        author=author,
        committer=committer or author,
        encoding=None,
        gpgsig=False,
        message=message,
    )


_PUBLIC = Ident(name="Pat Public", email="pat@example.com", timestamp=0, tz="+0000")
_COLLEAGUE = Ident(name="Alex Rivera", email="alex@colleague.example", timestamp=0, tz="+0000")


def test_identity_allow_matches_exact_name_and_email() -> None:
    assert is_identity_allowed("Pat Public", "pat@example.com", ["Pat Public <pat@example.com>"])
    assert not is_identity_allowed(
        "Pat Public", "pat@other.example", ["Pat Public <pat@example.com>"]
    )


def test_identity_allow_matches_bare_email() -> None:
    assert is_identity_allowed("Anyone", "pat@example.com", ["<pat@example.com>"])


def test_identity_allow_matches_bare_name() -> None:
    assert is_identity_allowed("Pat Public", "whatever@example.com", ["Pat Public"])


def test_non_allowlisted_identity_is_grouped() -> None:
    commits = {"c1": _commit("c1", author=_PUBLIC, committer=_COLLEAGUE, message="feat: x")}
    occurrences = collect_identities(commits, {})
    grouped = group_non_allowed_identities(occurrences, ["Pat Public <pat@example.com>"])
    assert list(grouped) == [_COLLEAGUE.display]
    assert {occ.role for occ in grouped[_COLLEAGUE.display]} == {"committer"}


def test_trailer_severity_email_is_medium_change_id_is_low() -> None:
    assert trailer_severity("Alex Rivera <alex@colleague.example>") == "medium"
    assert trailer_severity("I1234567890abcdef") == "low"


def test_collect_trailers_filters_to_flagged_keys() -> None:
    message = "feat: add thing\n\nCo-authored-by: Alex Rivera <alex@colleague.example>\n"
    commits = {"c1": _commit("c1", author=_PUBLIC, message=message)}
    trailers = collect_trailers(commits, ["Co-authored-by"])
    assert len(trailers) == 1
    assert trailers[0].key == "Co-authored-by"


def test_collect_timezone_offsets_skips_utc() -> None:
    utc_commit = _commit("c1", author=_PUBLIC, message="feat: x")
    offset_author = Ident(name="Pat Public", email="pat@example.com", timestamp=0, tz="+0200")
    offset_commit = _commit("c2", author=offset_author, committer=_PUBLIC, message="feat: y")
    offsets = collect_timezone_offsets({"c1": utc_commit, "c2": offset_commit})
    assert len(offsets) == 1
    assert offsets[0].commit == "c2"
    assert offsets[0].role == "author"
    assert offsets[0].tz == "+0200"
