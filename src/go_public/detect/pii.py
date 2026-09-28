"""Personal data: emails, phone numbers and flagged names (product spec item 3;
stage-3.md).

Every check here is content-only (no `path`/`commit` dependence), so a `PiiDetector`
can be built once per scan and its `detect()` called once per blob/message/field,
same as every other stage-3 detector (`scan.py` attributes the result to every
occurrence afterwards, exactly like the stage-3a fix to `detect/secrets.py`).
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
#: with a leading `+`, which the product spec says are "always detected" regardless
#: of `[pii] phone_regions`.
_INTERNATIONAL_REGION = "ZZ"


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
        seen: dict[tuple[int, int], Detection] = {}
        for region in self._regions:
            matcher = phonenumbers.PhoneNumberMatcher(
                text, region, leniency=phonenumbers.Leniency.VALID
            )
            for match in matcher:
                span = (match.start, match.start + len(match.raw_string))
                if span in seen:
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
