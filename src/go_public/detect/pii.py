"""Personal data: emails, phone numbers and flagged names.

Phone trade-off: a national-format candidate (no leading `+`) must carry a
separator (space, `-`, `.`, parentheses) or a trunk prefix (a leading `0`, or a
leading `1` on an 11-digit run), because `phonenumbers` accepts plenty of bare digit
runs (lockfile sizes, ids, counters) as valid national numbers. The price is that a
bare, unseparated national number without a trunk prefix, or one shorter than ten digits,
is missed; numbers written with `+` are always detected. Lockfiles are skipped for phones altogether
(`scan.py`, same file list as the generic-entropy detector).

Numeric data is not a phone number either (found by scanning real repositories: SVG path
data, coordinate and probability tables, ZIP+4 codes). A national candidate is dropped when
it is glued to more digits or to a decimal/list separator (`.`, `,`, `-` next to a digit),
when it mixes `.` and `-`, when a dotted one has fewer than two dots or a group of fewer
than three digits after the first, when a later group is a single digit, or when it is
shaped like a US ZIP+4 code or a numeric date. Numbers written with `+` skip the group
rules but not the "glued to more digits" check. The cost: a national number written
`555.12.34` or with one-digit groups is missed.

Emails: a match inside URL credentials (`scheme://user:secret@host`, `scheme://user@host`) or
followed by an scp-style path (`git@host:owner/repo.git`) is a remote or a credential, not
a mailbox, and is skipped.

Every check here is content-only (no `path`/`commit` dependence), so a `PiiDetector`
can be built once per scan and its `detect()` called once per blob/message/field,
same as every other content-only detector (`scan.py` attributes the result to every
occurrence afterwards, as it does for `detect/secrets.py`).
"""

from __future__ import annotations

import phonenumbers
import re2

from go_public.detect.base import Detection
from go_public.detect.constants import is_reserved_email_domain

#: A reasonably permissive email pattern (RFC 5322 is not worth porting in full):
#: local part, `@`, then one or more dot-separated host labels ending in a
#: letters-only TLD of at least two characters.
_EMAIL_RE = re2.compile(
    r"\b[A-Za-z0-9][A-Za-z0-9._%+-]*@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
    r"\.[A-Za-z]{2,}\b"
)

#: phonenumbers' "unknown region" sentinel: matches only numbers already written
#: with a leading `+`, which are always detected regardless of
#: `[pii] phone_regions`.
_INTERNATIONAL_REGION = "ZZ"

#: A cheap, deliberately permissive prefilter for `_detect_phones` (candidate digit runs are
#: prefiltered with re2 for speed): an optional leading `+`,
#: then a run of digits and common phone punctuation (space, dot, dash, parens) at
#: least 7 characters long, ending in a digit. Every format `phonenumbers` matches
#: at `Leniency.VALID` — national or international, with or without separators —
#: has at least this many digit-ish characters, so this never produces a false
#: negative; it only skips the real `PhoneNumberMatcher` parsing when there is no
#: phone-shaped run at all.
_CANDIDATE_DIGIT_RUN_RE = re2.compile(r"\+?\d[\d\s().-]{5,}\d")

#: Four or more dot-separated groups of 1-3 digits: a version number or an IPv4-shaped
#: string. `phonenumbers` accepts some of these as valid national numbers, so they are
#: skipped (a real phone number is not written like this in the supported regions).
_DOTTED_QUAD_RE = re2.compile(r"\d{1,3}(?:\.\d{1,3}){3,}")


_SEPARATORS = frozenset(" -.()")
#: Still inside the authority part of a URL: `://`, then no `/`, `@` or space yet.
_URL_AUTHORITY_BEFORE_RE = re2.compile(r"://[^\s/@]*$")
_SCP_PATH_AFTER_RE = re2.compile(r"^:[\w.~-]+/")
#: A bare (unseparated) national candidate needs at least this many digits (a leading `0`
#: on a six-digit constant is not a trunk prefix).
_MIN_BARE_DIGITS = 10
_DATE_RE = re2.compile(r"\(?(?:\d{1,2}-\d{1,2}-\d{4}|\d{4}-\d{1,2}-\d{1,2})\)?")
_ZIP_PLUS4_RE = re2.compile(r"\d{5}-\d{4}")
_LIST_SEPARATORS = ".,-"


def _digit_groups(raw: str) -> list[str]:
    return [g for g in re2.split(r"\D+", raw) if g]


def _is_url_credential_or_scp_remote(text: str, start: int, end: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    if _URL_AUTHORITY_BEFORE_RE.search(text[line_start:start]):
        return True
    return bool(_SCP_PATH_AFTER_RE.match(text[end : end + 60]))


def _is_numeric_data(text: str, start: int, end: int, raw: str) -> bool:
    """True when the candidate is a slice of a longer number, a decimal or a list of
    numbers rather than a phone number (see the module docstring)."""
    if start > 0:
        before = text[start - 1]
        if before.isdigit():
            return True
        if before in _LIST_SEPARATORS and start > 1 and text[start - 2].isdigit():
            return True
    if end < len(text):
        after = text[end]
        if after.isdigit():
            return True
        if after in _LIST_SEPARATORS and end + 1 < len(text) and text[end + 1].isdigit():
            return True
    if raw.startswith("+"):
        return False
    if _ZIP_PLUS4_RE.fullmatch(raw) or _DATE_RE.fullmatch(raw):
        return True
    groups = _digit_groups(raw)
    if any(len(g) == 1 for g in groups[1:]):
        return True
    if "." in raw:
        if "-" in raw or raw.count(".") < 2:
            return True
        if any(len(g) < 3 for g in groups[1:]):
            return True
    return False


def _has_phone_shape(raw: str) -> bool:
    """`+` numbers always count; a national candidate needs a separator or a trunk
    prefix (see the module docstring)."""
    if raw.startswith("+") or any(ch in _SEPARATORS for ch in raw):
        return True
    if len(raw) < _MIN_BARE_DIGITS:
        return False
    return raw.startswith("0") or (raw.startswith("1") and len(raw) == 11)


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    return line, offset - last_nl


def _allowed_emails(identity_allow: tuple[str, ...]) -> frozenset[str]:
    """Every literal email address an `identity.allow` entry names (`"<email>"` or
    `"Name <email>"` forms); a bare `"Name"` entry allows no specific address."""
    allowed = set()
    for entry in identity_allow:
        entry = entry.strip()
        if entry.startswith("<") and entry.endswith(">"):
            allowed.add(entry[1:-1].strip().lower())
        elif "<" in entry and entry.endswith(">"):
            email = entry[entry.index("<") + 1 : -1].strip()
            allowed.add(email.lower())
    return frozenset(allowed)


def _compile_names(names: frozenset[str]) -> re2.Pattern | None:
    escaped = sorted({re2.escape(n) for n in names if n.strip()}, key=len, reverse=True)
    if not escaped:
        return None
    return re2.compile(r"(?i)\b(?:" + "|".join(escaped) + r")\b")


class PiiDetector:
    """Emails, phone numbers and configured/history names over one unit of text."""

    def __init__(
        self,
        *,
        phone_regions: tuple[str, ...] = ("US", "GB", "DE"),
        identity_allow: tuple[str, ...] = (),
        names: frozenset[str] = frozenset(),
    ) -> None:
        self._regions = tuple(dict.fromkeys((*phone_regions, _INTERNATIONAL_REGION)))
        self._allowed_emails = _allowed_emails(identity_allow)
        self._name_re = _compile_names(names)

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        found.extend(self._detect_emails(text))
        found.extend(self._detect_phones(text))
        found.extend(self._detect_names(text))
        return found

    def _detect_emails(self, text: str) -> list[Detection]:
        out = []
        for m in _EMAIL_RE.finditer(text):
            value = m.group(0)
            domain = value.rsplit("@", 1)[-1]
            if is_reserved_email_domain(domain):
                continue
            if value.lower() in self._allowed_emails:
                continue
            start, end = m.start(), m.end()
            if _is_url_credential_or_scp_remote(text, start, end):
                continue
            line, col = _line_col(text, start)
            out.append(
                Detection(
                    category="pii",
                    rule_id="pii-email",
                    severity="high",
                    start=start,
                    end=end,
                    line=line,
                    col=col,
                    value=value,
                    secret=False,
                )
            )
        return out

    def _detect_phones(self, text: str) -> list[Detection]:
        # Cheap re2 prefilter: `PhoneNumberMatcher` does real parsing work per
        # region, so skip it outright on text with no digit run long enough to be
        # any phone number at all (never a false negative: every supported format,
        # national or "+", needs at least this many consecutive digits somewhere).
        if not _CANDIDATE_DIGIT_RUN_RE.search(text):
            return []
        seen: dict[tuple[int, int], Detection] = {}
        for region in self._regions:
            matcher = phonenumbers.PhoneNumberMatcher(
                text, region, leniency=phonenumbers.Leniency.VALID
            )
            for match in matcher:
                span = (match.start, match.start + len(match.raw_string))
                if span in seen or _DOTTED_QUAD_RE.fullmatch(match.raw_string):
                    continue
                if not _has_phone_shape(match.raw_string):
                    continue
                if _is_numeric_data(text, span[0], span[1], match.raw_string):
                    continue
                line, col = _line_col(text, span[0])
                seen[span] = Detection(
                    category="pii",
                    rule_id="pii-phone",
                    severity="high",
                    start=span[0],
                    end=span[1],
                    line=line,
                    col=col,
                    value=match.raw_string,
                    secret=False,
                )
        return list(seen.values())

    def _detect_names(self, text: str) -> list[Detection]:
        if self._name_re is None:
            return []
        out = []
        for m in self._name_re.finditer(text):
            start, end = m.start(), m.end()
            line, col = _line_col(text, start)
            out.append(
                Detection(
                    category="pii",
                    rule_id="pii-name",
                    severity="high",
                    start=start,
                    end=end,
                    line=line,
                    col=col,
                    value=m.group(0),
                    secret=False,
                )
            )
        return out
