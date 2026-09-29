"""Organisation identifiers from the user's deny-list: terms with generated variants,
domains, raw regexes, ticket keys.

Applied to blob text, every path, ref names, commit/tag messages, identities and
binary field values (`scan.py` calls `detect()`/`detect_ref_or_path()` at each of
those call sites); content-only, so one `DenyDetector` is built per scan and its
methods called once per unit of text, same as `detect/pii.py`.
"""

from __future__ import annotations

import re2

from go_public.detect.base import Detection

#: A domain-shaped token: dot-separated labels, no `@` or path separators, so it
#: isolates the host part of a URL or an email address without needing to parse
#: either (domains, including subdomains, email domains and URLs).
_DOMAIN_TOKEN_RE = re2.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+\b"
)


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    return line, offset - last_nl


def _term_variants(term: str) -> list[str]:
    """`"Acme Corp"` -> `["Acme Corp", "Acme-Corp", "Acme_Corp", "AcmeCorp"]`.
    Case-insensitive matching already folds further casing
    differences (`acmecorp` == `AcmeCorp`), so variants are deduplicated by their
    lowercased form.
    """
    raw = (term, term.replace(" ", "-"), term.replace(" ", "_"), term.replace(" ", ""))
    seen: set[str] = set()
    variants = []
    for v in raw:
        lowered = v.lower()
        if v and lowered not in seen:
            seen.add(lowered)
            variants.append(v)
    return variants


def _is_alnum(ch: str) -> bool:
    return ch.isalnum()


def _left_boundary_ok(text: str, start: int) -> bool:
    if start == 0:
        return True
    prev = text[start - 1]
    if not _is_alnum(prev):
        return True
    return prev.islower() and text[start].isupper()


def _right_boundary_ok(text: str, end: int) -> bool:
    if end >= len(text):
        return True
    nxt = text[end]
    if not _is_alnum(nxt):
        return True
    return text[end - 1].islower() and nxt.isupper()


def _has_boundary(text: str, start: int, end: int) -> bool:
    """A match needs a boundary on each side: a non-alphanumeric character, the
    start or end of the text, or a lower-to-upper case change. So `AcmeCorpClient`
    matches (case change on both sides) and `falconry` does not match `Falcon`
    (lower-to-lower on the right).
    """
    return _left_boundary_ok(text, start) and _right_boundary_ok(text, end)


class DenyDetector:
    """Terms (with variants and the boundary rule), domains, raw regexes and ticket
    keys from `[deny]`, over one unit of text.
    """

    def __init__(
        self,
        *,
        terms: tuple[str, ...] = (),
        domains: tuple[str, ...] = (),
        regexes: tuple[str, ...] = (),
        ticket_keys: tuple[str, ...] = (),
    ) -> None:
        self._term_pattern = self._compile_terms(terms)
        self._domains = tuple(d.lower().strip(".") for d in domains if d.strip())
        self._regexes = tuple((pattern, re2.compile(pattern)) for pattern in regexes)
        self._ticket_pattern = self._compile_tickets(ticket_keys)

    @staticmethod
    def _compile_terms(terms: tuple[str, ...]) -> re2.Pattern | None:
        alts: list[str] = []
        for term in terms:
            alts.extend(re2.escape(v) for v in _term_variants(term))
        if not alts:
            return None
        alts.sort(key=len, reverse=True)
        return re2.compile("(?i)(?:" + "|".join(alts) + ")")

    @staticmethod
    def _compile_tickets(ticket_keys: tuple[str, ...]) -> re2.Pattern | None:
        keys = [k for k in ticket_keys if k.strip()]
        if not keys:
            return None
        alts = sorted((re2.escape(k) for k in keys), key=len, reverse=True)
        return re2.compile(r"(?i)\b(?:" + "|".join(alts) + r")-\d+\b")

    def detect(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        out.extend(self._detect_terms(text))
        out.extend(self._detect_domains(text))
        out.extend(self._detect_regexes(text))
        out.extend(self._detect_tickets(text))
        return out

    def _detect_terms(self, text: str) -> list[Detection]:
        if self._term_pattern is None:
            return []
        out = []
        for m in self._term_pattern.finditer(text):
            start, end = m.start(), m.end()
            if not _has_boundary(text, start, end):
                continue
            line, col = _line_col(text, start)
            out.append(
                Detection(
                    category="org-identifier",
                    rule_id="deny-term",
                    severity="high",
                    start=start,
                    end=end,
                    line=line,
                    col=col,
                    value=text[start:end],
                    secret=False,
                )
            )
        return out

    def _detect_domains(self, text: str) -> list[Detection]:
        if not self._domains:
            return []
        out = []
        for m in _DOMAIN_TOKEN_RE.finditer(text):
            token = m.group(0)
            lowered = token.lower()
            if not any(lowered == d or lowered.endswith("." + d) for d in self._domains):
                continue
            start, end = m.start(), m.end()
            line, col = _line_col(text, start)
            out.append(
                Detection(
                    category="org-identifier",
                    rule_id="deny-domain",
                    severity="high",
                    start=start,
                    end=end,
                    line=line,
                    col=col,
                    value=token,
                    secret=False,
                )
            )
        return out

    def _detect_regexes(self, text: str) -> list[Detection]:
        out = []
        for _pattern, compiled in self._regexes:
            for m in compiled.finditer(text):
                start, end = m.start(), m.end()
                if start == end:
                    continue
                line, col = _line_col(text, start)
                out.append(
                    Detection(
                        category="org-identifier",
                        rule_id="deny-regex",
                        severity="high",
                        start=start,
                        end=end,
                        line=line,
                        col=col,
                        value=text[start:end],
                        secret=False,
                    )
                )
        return out

    def _detect_tickets(self, text: str) -> list[Detection]:
        if self._ticket_pattern is None:
            return []
        out = []
        for m in self._ticket_pattern.finditer(text):
            start, end = m.start(), m.end()
            line, col = _line_col(text, start)
            out.append(
                Detection(
                    category="org-identifier",
                    rule_id="deny-ticket",
                    severity="high",
                    start=start,
                    end=end,
                    line=line,
                    col=col,
                    value=text[start:end],
                    secret=False,
                )
            )
        return out
