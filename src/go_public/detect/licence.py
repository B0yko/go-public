"""Licence identification by key phrases (product spec item 7; stage-3.md 3b;
`docs/adr/0009-licence-detection-by-key-phrases.md`). No legal analysis: text is
matched against known phrasing for common licences, nothing more, and the README
says so.

Scope: transition and missing-at-head tracking cover the canonical licence-file
family (`LICENSE*`/`LICENCE*`/`COPYING*`) and the three manifest `license` fields
product spec item 7 names (`pyproject.toml`, `package.json`, `Cargo.toml`) — a small,
path-identifiable set that needs reading only the blobs that are actually relevant,
rather than every blob's content in history. An `SPDX-License-Identifier` header in
an arbitrary source file is still identified where it appears (`identify_spdx_header`,
used by the proprietary/confidential notice scan below, which already reads every
blob's text once as part of the normal pipeline) but does not feed transition
tracking; see STATUS.md.
"""

from __future__ import annotations

import json
import tomllib

import re2

from go_public.detect.base import Detection

#: Tried in order; the first whose every phrase matches wins. More specific licences
#: (whose text is a superset of a more general one's, e.g. LGPL referencing "General
#: Public License") are tried first.
_KEY_PHRASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Unlicense", ("free and unencumbered software", "public domain")),
    ("AGPL-3.0", ("gnu affero general public license",)),
    ("LGPL-3.0", ("gnu lesser general public license", "version 3")),
    ("LGPL-2.1", ("gnu lesser general public license", "version 2.1")),
    ("GPL-3.0", ("gnu general public license", "version 3")),
    ("GPL-2.0", ("gnu general public license", "version 2")),
    ("MPL-2.0", ("mozilla public license", "2.0")),
    ("Apache-2.0", ("apache license", "version 2.0")),
    ("BSD-3-Clause", ("redistribution and use in source and binary forms", "neither the name")),
    ("BSD-2-Clause", ("redistribution and use in source and binary forms",)),
    ("ISC", ("permission to use, copy, modify, and/or distribute this software",)),
    ("MIT", ("permission is hereby granted, free of charge",)),
)

_PROPRIETARY_KEYWORDS = ("confidential", "proprietary")
_PERMISSION_GRANT_PHRASES = (
    "permission is hereby granted",
    "permission is granted",
    "licensed under",
    "licenced under",
)

#: SPDX identifiers product spec item 7 names, mapped to the same canonical labels
#: `identify_licence_text` returns (so a transition can compare across both sources).
_SPDX_TO_LABEL: dict[str, str] = {
    "MIT": "MIT",
    "Apache-2.0": "Apache-2.0",
    "BSD-2-Clause": "BSD-2-Clause",
    "BSD-3-Clause": "BSD-3-Clause",
    "ISC": "ISC",
    "MPL-2.0": "MPL-2.0",
    "Unlicense": "Unlicense",
}
for _base, _label in (
    ("GPL-2.0", "GPL-2.0"),
    ("GPL-3.0", "GPL-3.0"),
    ("LGPL-2.1", "LGPL-2.1"),
    ("LGPL-3.0", "LGPL-3.0"),
    ("AGPL-3.0", "AGPL-3.0"),
):
    for _suffix in ("", "-only", "-or-later"):
        _SPDX_TO_LABEL[f"{_base}{_suffix}"] = _label

_SPDX_RE = re2.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+-]+)")
_COPYRIGHT_RE = re2.compile(r"(?i)copyright\s*(?:\([cC]\)|©)?\s*\d{4}(?:-\d{4})?,?\s*([^\n\r]+)")

_LICENCE_FILE_PREFIXES = ("LICENSE", "LICENCE", "COPYING")
_MANIFEST_BASENAMES = frozenset({"pyproject.toml", "package.json", "Cargo.toml"})


def is_licence_file_path(path: str) -> bool:
    basename = path.rsplit("/", 1)[-1]
    return basename.startswith(_LICENCE_FILE_PREFIXES)


def is_manifest_path(path: str) -> bool:
    return path.rsplit("/", 1)[-1] in _MANIFEST_BASENAMES


def is_licence_relevant_path(path: str) -> bool:
    return is_licence_file_path(path) or is_manifest_path(path)


def identify_licence_text(text: str) -> str:
    """Classify licence *text* by key phrase. "proprietary" needs "confidential"/
    "proprietary" wording, or an all-rights-reserved notice with no permission-grant
    phrase; anything else unmatched is "unknown"."""
    lowered = text.lower()
    for label, phrases in _KEY_PHRASES:
        if all(phrase in lowered for phrase in phrases):
            return label
    if any(word in lowered for word in _PROPRIETARY_KEYWORDS):
        return "proprietary"
    has_grant = any(phrase in lowered for phrase in _PERMISSION_GRANT_PHRASES)
    if "all rights reserved" in lowered and not has_grant:
        return "proprietary"
    return "unknown"


def identify_spdx_header(text: str) -> str | None:
    """The first `SPDX-License-Identifier:` value, mapped to a canonical label (an
    id this module does not recognise still counts as found, labelled "unknown" so a
    transition away from it is still visible)."""
    match = _SPDX_RE.search(text)
    if match is None:
        return None
    return _SPDX_TO_LABEL.get(match.group(1), "unknown")


def _manifest_licence_field(basename: str, content: bytes) -> str | None:
    text = content.decode("utf-8", errors="replace")
    try:
        if basename == "pyproject.toml":
            data = tomllib.loads(text)
            project = data.get("project")
            if isinstance(project, dict):
                license_ = project.get("license")
                if isinstance(license_, str):
                    return license_
                if isinstance(license_, dict):
                    license_text = license_.get("text")
                    if isinstance(license_text, str):
                        return license_text
            tool = data.get("tool")
            poetry = tool.get("poetry") if isinstance(tool, dict) else None
            if isinstance(poetry, dict):
                poetry_license = poetry.get("license")
                if isinstance(poetry_license, str):
                    return poetry_license
            return None
        if basename == "package.json":
            data = json.loads(text)
            license_ = data.get("license") if isinstance(data, dict) else None
            return license_ if isinstance(license_, str) else None
        if basename == "Cargo.toml":
            data = tomllib.loads(text)
            package = data.get("package")
            if isinstance(package, dict) and isinstance(package.get("license"), str):
                return str(package["license"])
            return None
    except (tomllib.TOMLDecodeError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return None


def identify_path_content(path: str, content: bytes) -> str | None:
    """The canonical licence label this path/content pair declares, or `None` when
    the path isn't one `is_licence_relevant_path` recognises. A manifest with no
    recognisable `license` field returns `None` too (it declares nothing, which is
    different from declaring an unrecognised value)."""
    basename = path.rsplit("/", 1)[-1]
    if is_licence_file_path(path):
        text = content.decode("utf-8", errors="replace")
        return identify_licence_text(text)
    if basename in _MANIFEST_BASENAMES:
        field = _manifest_licence_field(basename, content)
        if field is None:
            return None
        return _SPDX_TO_LABEL.get(field, identify_licence_text(field))
    return None


def extract_copyright_holder(text: str) -> str | None:
    match = _COPYRIGHT_RE.search(text)
    if match is None:
        return None
    holder = match.group(1).strip().rstrip(".").strip()
    return holder or None


#: A notice, not a mention: the word must open the line (after optional leading
#: whitespace and a single comment marker), the shape of an actual banner ("//
#: Confidential", "Proprietary and confidential. All rights reserved.") rather than
#: prose that merely discusses the concept — including this file's own docstrings and
#: `_PROPRIETARY_KEYWORDS` itself, which a plain substring-anywhere search would
#: self-flag on go-public's own self-scan.
_NOTICE_LINE_RE = re2.compile(r"(?im)^[ \t]*(?:#|//|/\*|\*|--)?[ \t]*(Confidential|Proprietary)\b")


def detect_notice(text: str) -> Detection | None:
    """A proprietary/confidential notice anywhere in a blob or message (product spec
    item 7: "anywhere in history..., at high severity"; stage-3.md: "licence files,
    SPDX/header comment blocks at file top"). Deliberately runs over any text, not
    just licence files, since a notice can sit at the top of any source file."""
    match = _NOTICE_LINE_RE.search(text)
    if match is None:
        return None
    start = match.start()
    line = text.count("\n", 0, start) + 1
    line_start = text.rfind("\n", 0, start) + 1
    col = start - line_start + 1
    line_end = text.find("\n", start)
    value = text[start : line_end if line_end != -1 else None].strip()
    return Detection(
        category="licence",
        rule_id="licence-proprietary",
        severity="high",
        start=start,
        end=start + len(value),
        line=line,
        col=col,
        value=value[:80],
        secret=False,
    )
