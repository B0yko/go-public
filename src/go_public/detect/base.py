"""The shared detector contract (architecture.md "Scan units and routing") plus blob
routing: magic bytes, the NUL/UTF-16 text check, and the `max_scan_mb` gate.

`detect/secrets.py` (stage 2a) is the only detector that exists yet; `scan.py`
(stage 2b) is the only caller of the routing functions here. Real binary field
extraction (Pillow/pypdf/defusedxml) is stage 3b's `detect/binary_meta.py`;
`extract_binary_fields` is a stub that always returns no fields, so a JPEG/PNG/WebP/
TIFF/PDF/OOXML blob is routed correctly now (unit-tested) and scan.py already has
the wiring to run text detectors over whatever fields a later stage's extractor
returns, without any change to scan.py itself.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from typing import Any

#: Magic-byte signatures (product spec item 6 / architecture "Scan units and
#: routing"). Checked in this order; the first match wins.
_JPEG_MAGIC = b"\xff\xd8\xff"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_TIFF_MAGIC_LE = b"II*\x00"
_TIFF_MAGIC_BE = b"MM\x00*"
_WEBP_RIFF = b"RIFF"
_WEBP_TAG = b"WEBP"
_ZIP_MAGIC = b"PK\x03\x04"
_PDF_MAGIC = b"%PDF-"
#: "PDF signature within first 1024 bytes" (stage-2.md): some PDFs carry junk bytes
#: (a shebang, a BOM) before the `%PDF-` header, which real PDF readers tolerate.
_PDF_SCAN_WINDOW = 1024
_NUL_SCAN_WINDOW = 8000
_UTF16_LE_BOM = b"\xff\xfe"
_UTF16_BE_BOM = b"\xfe\xff"

#: Blob kinds that carry extractable text fields once `detect/binary_meta.py`
#: (stage 3b) exists. Any other non-text kind (`archive`, `binary`, `large`) is
#: never scanned by text detectors.
BINARY_KINDS = frozenset({"jpeg", "png", "tiff", "webp", "pdf", "ooxml"})

#: OOXML (docx/xlsx/pptx) is a zip with this manifest entry plus a part directory
#: from one of the three Office document kinds (product spec item 6).
_OOXML_MARKER = "[Content_Types].xml"
_OOXML_PART_PREFIXES = ("word/", "xl/", "ppt/", "docProps/")


@dataclass(frozen=True, slots=True)
class UnitCtx:
    """Per-call context a detector needs beyond the text itself.

    `path` and `commit` drive gitleaks-style path- and commit-scoped allowlists and
    path-only rules. Both default to "" for units with no natural path or commit
    (an identity string, a ref name). A blob that occurs at several (path, commit)
    pairs is scanned once per distinct occurrence by the caller, since path- and
    commit-dependent allowlist decisions can differ per occurrence (architecture.md,
    stage-2 notes).
    """

    path: str = ""
    commit: str = ""


@dataclass(frozen=True, slots=True)
class Detection:
    """One match, before the scan pipeline (stage 2b) turns it into a
    `model.Finding` (location, fingerprint, group_id, preview, ...).
    """

    category: str
    rule_id: str
    severity: str
    start: int
    end: int
    line: int
    col: int
    value: str
    secret: bool
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TextUnit:
    """One thing to run text detectors over, outside the blob worker pool.

    Blobs are handled by `scan.py`'s worker pool directly (each worker already has
    the blob content from its own `cat-file --batch`); a `TextUnit` is for the
    smaller, already-in-memory units — a commit or tag message, and (stage 3) an
    identity string, a trailer value, a ref name, a path. Only `kind in
    {"commit_message", "tag_message"}` is produced by stage 2b's `scan.py`, since
    only the secrets detector exists so far and it runs on messages (architecture:
    "Messages (commit + tag) go through the secret detector too").
    """

    kind: str
    text: str
    ctx: UnitCtx
    commit: str | None = None
    tag: str | None = None


@dataclass(frozen=True, slots=True)
class RouteResult:
    """Where a blob's content goes next. `kind` is one of `BINARY_KINDS`,
    `"archive"` (zip/jar/tar, not OOXML), `"binary"` (NUL-containing, not any known
    magic), `"large"` (would be text but exceeds `max_scan_mb`), or `"text"` (decoded
    content ready for the text detectors, in `.text`).
    """

    kind: str
    text: str | None = None


def _is_ooxml(content: bytes) -> bool:
    """A zip is OOXML when it carries the Office manifest and a document part."""
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = archive.namelist()
    except (zipfile.BadZipFile, OSError, NotImplementedError, ValueError):
        return False
    if _OOXML_MARKER not in names:
        return False
    return any(name.startswith(_OOXML_PART_PREFIXES) for name in names)


def _as_text_or_large(text: str, *, max_scan_mb: int) -> RouteResult:
    if len(text.encode("utf-8", errors="surrogateescape")) > max_scan_mb * 1024 * 1024:
        return RouteResult(kind="large")
    return RouteResult(kind="text", text=text)


def route_blob(content: bytes, *, max_scan_mb: int = 10) -> RouteResult:
    """Classify one blob's raw bytes (architecture.md "Scan units and routing").

    Magic bytes first (image/PDF/zip formats); a ZIP is further split into OOXML vs.
    a plain archive. Otherwise a UTF-16 BOM decodes straight to text (a NUL check
    would otherwise misclassify it as binary); failing that, a NUL in the first 8,000
    bytes means binary; everything else is text, gated by `max_scan_mb`.
    """
    if content.startswith(_JPEG_MAGIC):
        return RouteResult(kind="jpeg")
    if content.startswith(_PNG_MAGIC):
        return RouteResult(kind="png")
    if content.startswith(_TIFF_MAGIC_LE) or content.startswith(_TIFF_MAGIC_BE):
        return RouteResult(kind="tiff")
    if content[:4] == _WEBP_RIFF and content[8:12] == _WEBP_TAG:
        return RouteResult(kind="webp")
    if _PDF_MAGIC in content[:_PDF_SCAN_WINDOW]:
        return RouteResult(kind="pdf")
    if content.startswith(_ZIP_MAGIC):
        return RouteResult(kind="ooxml" if _is_ooxml(content) else "archive")

    if content[:2] in (_UTF16_LE_BOM, _UTF16_BE_BOM):
        # The plain "utf-16" codec both picks the endianness from the BOM and
        # strips it from the decoded text; "utf-16-le"/"-be" would decode the BOM
        # bytes themselves into a leading U+FEFF character.
        try:
            text = content.decode("utf-16")
        except UnicodeDecodeError:
            return RouteResult(kind="binary")
        return _as_text_or_large(text, max_scan_mb=max_scan_mb)

    if b"\x00" in content[:_NUL_SCAN_WINDOW]:
        return RouteResult(kind="binary")

    text = content.decode("utf-8", errors="replace")
    return _as_text_or_large(text, max_scan_mb=max_scan_mb)


def extract_binary_fields(kind: str, content: bytes) -> dict[str, str]:
    """Extract named text fields (EXIF tags, PDF Info/XMP, OOXML docProps, PNG text
    chunks) for the text detectors to scan (location kind `binary_field`).

    Stub for stage 2b: real extraction is stage 3b's `detect/binary_meta.py`
    (Pillow/pypdf/defusedxml). Returning no fields for every `kind in BINARY_KINDS`
    means `scan.py`'s wiring (route -> extract -> run text detectors per field) is
    exercised end-to-end now without producing findings yet, matching stage-2.md's
    scope.
    """
    del kind, content
    return {}
