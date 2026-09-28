"""Commit metadata: identities, trailers and timezone offsets (product spec item 10;
stage-3.md). Message text itself already runs through every text detector in
`scan.py`'s normal blob/message pipeline; this module covers the metadata that lives
outside the message body (author/committer/tagger identities, parsed trailers, raw
timezone offsets).
"""

from __future__ import annotations

import re2

from go_public.git.objects import CommitObj, Ident, TagObj, parse_trailers

#: A crude "looks like a name or email" heuristic for trailer severity (architecture.
#: md "Default severities": "trailers with a name or email" = medium, "trailers
#: without name/email (Change-Id)" = low). An email is unambiguous; two capitalised
#: words is a reasonable proxy for "Full Name" without needing name detection.
_NAME_LIKE_RE = re2.compile(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b")


def is_identity_allowed(name: str, email: str, allow_entries: list[str]) -> bool:
    """`identity.allow` entries: `"Name <email>"` (exact, email case-insensitive),
    `"<email>"` (any name) or `"Name"` (any email) — architecture.md "Config".
    """
    email_lower = email.lower()
    for raw in allow_entries:
        entry = raw.strip()
        if entry.startswith("<") and entry.endswith(">"):
            if entry[1:-1].strip().lower() == email_lower:
                return True
        elif "<" in entry and entry.endswith(">"):
            allowed_name, _, rest = entry.partition("<")
            if allowed_name.strip() == name and rest[:-1].strip().lower() == email_lower:
                return True
        elif entry == name:
            return True
    return False


class IdentityOccurrence:
    __slots__ = ("identity", "role", "commit", "tag")

    def __init__(self, *, identity: str, role: str, commit: str | None, tag: str | None) -> None:
        self.identity = identity
        self.role = role
        self.commit = commit
        self.tag = tag


def collect_identities(
    commits: dict[str, CommitObj], tags: dict[str, TagObj]
) -> list[IdentityOccurrence]:
    """Every author/committer identity in `commits` and every tagger identity in
    `tags`, one occurrence per (identity, role, commit-or-tag)."""
    out: list[IdentityOccurrence] = []
    for oid, commit in commits.items():
        out.append(
            IdentityOccurrence(identity=commit.author.display, role="author", commit=oid, tag=None)
        )
        out.append(
            IdentityOccurrence(
                identity=commit.committer.display, role="committer", commit=oid, tag=None
            )
        )
    for oid, tag in tags.items():
        if tag.tagger is not None:
            out.append(
                IdentityOccurrence(identity=tag.tagger.display, role="tagger", commit=None, tag=oid)
            )
    return out


def group_non_allowed_identities(
    occurrences: list[IdentityOccurrence], allow: list[str]
) -> dict[str, list[IdentityOccurrence]]:
    """Every distinct identity string not on `identity.allow`, grouped for one
    `identity`-category finding each (architecture.md: "one finding per distinct
    identity string; roles and commits in extra/commits").
    """
    grouped: dict[str, list[IdentityOccurrence]] = {}
    for occ in occurrences:
        name, _, rest = occ.identity.partition(" <")
        email = rest[:-1] if rest.endswith(">") else ""
        if is_identity_allowed(name, email, allow):
            continue
        grouped.setdefault(occ.identity, []).append(occ)
    return grouped


class TrailerOccurrence:
    __slots__ = ("commit", "key", "value")

    def __init__(self, *, commit: str, key: str, value: str) -> None:
        self.commit = commit
        self.key = key
        self.value = value


def collect_trailers(
    commits: dict[str, CommitObj], flagged_keys: list[str]
) -> list[TrailerOccurrence]:
    """Trailers in every commit message whose key is on `[trailers] flag`
    (case-insensitive)."""
    flagged_lower = {k.lower() for k in flagged_keys}
    out: list[TrailerOccurrence] = []
    for oid, commit in commits.items():
        for trailer in parse_trailers(commit.message):
            if trailer.key.lower() in flagged_lower:
                out.append(TrailerOccurrence(commit=oid, key=trailer.key, value=trailer.value))
    return out


def trailer_severity(value: str) -> str:
    if "@" in value or _NAME_LIKE_RE.search(value):
        return "medium"
    return "low"


class TimezoneOccurrence:
    __slots__ = ("commit", "role", "tz")

    def __init__(self, *, commit: str, role: str, tz: str) -> None:
        self.commit = commit
        self.role = role
        self.tz = tz


def collect_timezone_offsets(commits: dict[str, CommitObj]) -> list[TimezoneOccurrence]:
    """One occurrence per non-UTC author/committer offset (architecture.md: "Non-UTC
    timezone offsets, reported at info level")."""
    out: list[TimezoneOccurrence] = []
    for oid, commit in commits.items():
        idents: tuple[tuple[str, Ident], ...] = (
            ("author", commit.author),
            ("committer", commit.committer),
        )
        for role, ident in idents:
            if ident.tz != "+0000":
                out.append(TimezoneOccurrence(commit=oid, role=role, tz=ident.tz))
    return out
