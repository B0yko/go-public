"""Local paths and network identifiers (product spec item 5; stage-3.md): absolute
paths that reveal a username, macOS temp paths, private IPs, internal hostnames and
`.gitmodules` URLs to private hosts.

Content-only (no `path`/`commit` dependence beyond the `.gitmodules` special case,
which `scan.py` opts into per blob by passing `is_gitmodules=True`), so one
`PathsNetworkDetector` is built per scan and its `detect()` called once per blob/
message/field.
"""

from __future__ import annotations

import re2

from go_public.detect.base import Detection
from go_public.detect.constants import (
    MACOS_TEMP_PATH_PREFIX,
    USER_PATH_PREFIXES,
    WINDOWS_USER_PATH_FSLASH_PREFIX,
    WINDOWS_USER_PATH_PREFIX,
    is_private_ip,
)

_USER_SEGMENT = r"[A-Za-z0-9._-]+"


def _windows_prefix_pattern(prefix: str) -> str:
    """`prefix`'s backslashes, each allowed to appear doubled too (a Windows path
    JSON-escapes each `\\` as `\\\\`, so the raw text a JSON-encoded blob carries has
    two backslash characters per separator)."""
    return str(re2.escape(prefix)).replace("\\\\", r"\\{1,2}")


#: `/Users/<user>/`, `/home/<user>/`, `C:\Users\<user>\` (also a doubled backslash,
#: as it appears JSON-escaped, and the forward-slash spelling some tools use for
#: Windows paths) — every prefix comes from `detect/constants.py`, per
#: conventions.md ("only constants.py may hold ... path prefixes").
_USER_PATH_RE = re2.compile(
    "(?:"
    + "|".join(re2.escape(p) for p in USER_PATH_PREFIXES)
    + ")"
    + _USER_SEGMENT
    + "/"
    + "|"
    + _windows_prefix_pattern(WINDOWS_USER_PATH_PREFIX)
    + _USER_SEGMENT
    + r"\\{1,2}"
    + "|"
    + re2.escape(WINDOWS_USER_PATH_FSLASH_PREFIX)
    + _USER_SEGMENT
    + "/"
)

_MACOS_TEMP_RE = re2.compile(re2.escape(MACOS_TEMP_PATH_PREFIX) + r"[\w./-]*")

_IPV4_TOKEN_RE = re2.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
#: RFC 4193 unique local addresses always start with `fc` or `fd` (the "locally
#: assigned" `L` bit set); anchoring on that keeps this cheap and avoids matching
#: unrelated hex runs.
_IPV6_ULA_RE = re2.compile(r"(?i)\bf[cd][0-9a-f]{2}:[0-9a-f:]{2,35}\b")

_HOST_TOKEN_RE = re2.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+\b"
)

#: Usernames that are placeholders in documentation, not people.
_PLACEHOLDER_USERS = frozenset(
    {
        "user",
        "username",
        "yourname",
        "your-name",
        "yourusername",
        "your-username",
        "name",
        "you",
        "me",
        "example",
    }
)

#: What precedes/follows a `.local`-style token that makes it a code reference rather than a
#: host: `from werkzeug.local import X`, `import ***REMOVED***`, `threading.local()`, `***REMOVED***.b`.
_IMPORT_BEFORE_RE = re2.compile(r"(?:^|\s)(?:from|import)\s+$")
_CODE_AFTER_RE = re2.compile(r"^(?:\(|\s+import\b|\.[A-Za-z_])")

_GITMODULES_URL_RE = re2.compile(r"(?m)^\s*url\s*=\s*(\S+)\s*$")
_URL_HOST_RE = re2.compile(r"(?:://|@)([A-Za-z0-9.-]+)")


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    return line, offset - last_nl


def _is_placeholder_user(value: str) -> bool:
    """A home-directory path whose user segment is a documentation placeholder such as
    `user`, `username` or `you`."""
    segment = re2.split(r"[\\/]+", value.rstrip("\\/"))[-1]
    return segment.lower() in _PLACEHOLDER_USERS


def _is_code_reference(text: str, start: int, end: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    if _IMPORT_BEFORE_RE.search(text[line_start:start]):
        return True
    return bool(_CODE_AFTER_RE.match(text[end : end + 12]))


def _host_from_url(value: str) -> str:
    m = _URL_HOST_RE.search(value)
    if m:
        return str(m.group(1))
    return value.split("/", 1)[0]


class PathsNetworkDetector:
    """User/temp paths, private IPs and internal hostnames over one unit of text."""

    def __init__(
        self,
        *,
        allowed_path_prefixes: tuple[str, ...] = (),
        internal_suffixes: tuple[str, ...] = (),
        deny_domains: tuple[str, ...] = (),
    ) -> None:
        self._allowed_prefixes = allowed_path_prefixes
        self._internal_suffixes = tuple(s.lower() for s in internal_suffixes)
        self._deny_domains = tuple(d.lower().strip(".") for d in deny_domains if d.strip())

    def detect(self, text: str, *, is_gitmodules: bool = False) -> list[Detection]:
        out: list[Detection] = []
        out.extend(self._detect_user_paths(text))
        out.extend(self._detect_macos_temp(text))
        out.extend(self._detect_private_ips(text))
        out.extend(self._detect_internal_hosts(text))
        if is_gitmodules:
            out.extend(self._detect_gitmodules_urls(text))
        return out

    def _is_allowed_path(self, matched: str) -> bool:
        return any(matched.startswith(prefix) for prefix in self._allowed_prefixes)

    def _detect_user_paths(self, text: str) -> list[Detection]:
        out = []
        for m in _USER_PATH_RE.finditer(text):
            start, end = m.start(), m.end()
            value = text[start:end]
            if self._is_allowed_path(value):
                continue
            if _is_placeholder_user(value):
                continue
            line, col = _line_col(text, start)
            out.append(
                Detection(
                    category="local-path",
                    rule_id="user-path",
                    severity="medium",
                    start=start,
                    end=end,
                    line=line,
                    col=col,
                    value=value,
                    secret=False,
                )
            )
        return out

    def _detect_macos_temp(self, text: str) -> list[Detection]:
        out = []
        for m in _MACOS_TEMP_RE.finditer(text):
            start, end = m.start(), m.end()
            line, col = _line_col(text, start)
            out.append(
                Detection(
                    category="local-path",
                    rule_id="macos-temp-path",
                    severity="medium",
                    start=start,
                    end=end,
                    line=line,
                    col=col,
                    value=text[start:end],
                    secret=False,
                )
            )
        return out

    def _detect_private_ips(self, text: str) -> list[Detection]:
        out = []
        for pattern in (_IPV4_TOKEN_RE, _IPV6_ULA_RE):
            for m in pattern.finditer(text):
                value = m.group(0)
                if not is_private_ip(value):
                    continue
                start, end = m.start(), m.end()
                line, col = _line_col(text, start)
                out.append(
                    Detection(
                        category="network",
                        rule_id="private-ip",
                        severity="medium",
                        start=start,
                        end=end,
                        line=line,
                        col=col,
                        value=value,
                        secret=False,
                    )
                )
        return out

    def _is_internal_host(self, lowered: str) -> bool:
        if any(lowered.endswith(suffix) for suffix in self._internal_suffixes):
            return True
        return any(lowered == d or lowered.endswith("." + d) for d in self._deny_domains)

    def _detect_internal_hosts(self, text: str) -> list[Detection]:
        if not self._internal_suffixes and not self._deny_domains:
            return []
        out = []
        for m in _HOST_TOKEN_RE.finditer(text):
            token = m.group(0)
            if not self._is_internal_host(token.lower()):
                continue
            start, end = m.start(), m.end()
            if _is_code_reference(text, start, end):
                continue
            line, col = _line_col(text, start)
            out.append(
                Detection(
                    category="network",
                    rule_id="internal-host",
                    severity="medium",
                    start=start,
                    end=end,
                    line=line,
                    col=col,
                    value=token,
                    secret=False,
                )
            )
        return out

    def _detect_gitmodules_urls(self, text: str) -> list[Detection]:
        out = []
        for m in _GITMODULES_URL_RE.finditer(text):
            value = m.group(1)
            host = _host_from_url(value)
            if not (self._is_internal_host(host.lower()) or is_private_ip(host)):
                continue
            start, end = m.start(1), m.end(1)
            line, col = _line_col(text, start)
            out.append(
                Detection(
                    category="network",
                    rule_id="private-submodule-url",
                    severity="medium",
                    start=start,
                    end=end,
                    line=line,
                    col=col,
                    value=value,
                    secret=False,
                )
            )
        return out
