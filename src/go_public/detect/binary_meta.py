"""Binary metadata extraction (product spec item 6; stage-3.md 3b): JPEG/TIFF/WebP
EXIF, PNG chunks (parsed directly, not through Pillow's own limited exposure), PDF
Info/XMP and OOXML docProps/comments/tracked-changes.

`extract_fields` is what `detect/base.py`'s `extract_binary_fields` delegates to
(architecture.md "Scan units and routing": magic-byte routed, extracted values then
go through the text detectors under location kind `binary_field`). Each `BinaryField`
also carries go-public's *own* classification (rule id + severity) for the field's
mere presence, independent of whatever the text detectors separately find in its
value (architecture.md rule ids: exif-gps, exif-person, exif-org, exif-software,
png-text, png-time, png-exif, pdf-info, pdf-xmp, ooxml-core, ooxml-app, ooxml-custom,
ooxml-comment-author, ooxml-revision-author).

Every parser below is defensive: malformed/adversarial bytes (a truncated PNG, a
zip claiming to be OOXML but missing a part) must never crash a scan, only yield
fewer fields.
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET
from PIL import Image
from PIL.ExifTags import IFD
from PIL.ExifTags import Base as ExifTag
from pypdf import PdfReader


@dataclass(frozen=True, slots=True)
class BinaryField:
    """One named value extracted from a binary blob."""

    name: str
    value: str
    rule_id: str
    severity: str


#: EXIF tags treated as naming a person (product spec item 6): "Artist, XPAuthor,
#: CameraOwnerName, ... ImageDescription/UserComment when non-empty".
_EXIF_PERSON_TAGS: dict[int, str] = {
    ExifTag.Artist.value: "Artist",
    ExifTag.ImageDescription.value: "ImageDescription",
    ExifTag.UserComment.value: "UserComment",
    ExifTag.XPAuthor.value: "XPAuthor",
    ExifTag.CameraOwnerName.value: "CameraOwnerName",
}
#: EXIF tags treated as naming an organisation.
_EXIF_ORG_TAGS: dict[int, str] = {
    ExifTag.Copyright.value: "Copyright",
    ExifTag.HostComputer.value: "HostComputer",
}
_EXIF_SOFTWARE_TAGS: dict[int, str] = {ExifTag.Software.value: "Software"}


def _coerce_exif_text(value: Any) -> str:
    """EXIF text values arrive as `str`, UTF-16LE `bytes` (the `XP*` tags) or, rarely,
    other byte encodings; never raise on an unexpected shape."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-16-le")
        except UnicodeDecodeError:
            text = value.decode("utf-8", errors="replace")
        return text.rstrip("\x00").strip()
    return str(value).strip()


def _gps_summary(gps_ifd: dict[int, Any]) -> str:
    """`"lat,lon"` in decimal degrees when the IFD has the usual ref/DMS tags, else
    just a note that GPS data is present (some writers use fewer tags)."""
    try:
        lat = _dms_to_decimal(gps_ifd[2], gps_ifd.get(1, "N"))
        lon = _dms_to_decimal(gps_ifd[4], gps_ifd.get(3, "E"))
    except (KeyError, TypeError, ValueError, IndexError):
        return "GPS data present"
    return f"{lat:.6f},{lon:.6f}"


def _dms_to_decimal(dms: Any, ref: Any) -> float:
    degrees, minutes, seconds = (float(part) for part in dms)
    value = degrees + minutes / 60 + seconds / 3600
    return -value if ref in ("S", "W", b"S", b"W") else value


def _exif_fields(exif: Image.Exif) -> list[BinaryField]:
    fields: list[BinaryField] = []
    try:
        gps = exif.get_ifd(IFD.GPSInfo)
    except Exception:  # noqa: BLE001 - malformed IFD data must never crash a scan
        gps = {}
    if gps:
        fields.append(BinaryField("GPSInfo", _gps_summary(gps), "exif-gps", "high"))
    for tag_id, name in _EXIF_PERSON_TAGS.items():
        text = _coerce_exif_text(exif.get(tag_id))
        if text:
            fields.append(BinaryField(name, text, "exif-person", "medium"))
    for tag_id, name in _EXIF_ORG_TAGS.items():
        text = _coerce_exif_text(exif.get(tag_id))
        if text:
            fields.append(BinaryField(name, text, "exif-org", "medium"))
    for tag_id, name in _EXIF_SOFTWARE_TAGS.items():
        text = _coerce_exif_text(exif.get(tag_id))
        if text:
            fields.append(BinaryField(name, text, "exif-software", "low"))
    return fields


def _extract_image_exif(content: bytes) -> list[BinaryField]:
    """JPEG/TIFF/WebP: `Image.open(...).getexif()` reads all three uniformly."""
    try:
        with Image.open(io.BytesIO(content)) as img:
            exif = img.getexif()
    except Exception:  # noqa: BLE001 - not a valid image we can open
        return []
    return _exif_fields(exif)


# -- PNG: chunks parsed directly (Pillow exposes tEXt/iTXt via `.text` but not tIME,
# and stage-3.md asks for direct parsing) -------------------------------------------

_PNG_SIGNATURE_LEN = 8
_PNG_TEXT_PERSON_KEYWORDS = frozenset({"author", "artist", "copyright"})


def _iter_png_chunks(content: bytes) -> list[tuple[str, bytes]]:
    chunks: list[tuple[str, bytes]] = []
    pos = _PNG_SIGNATURE_LEN
    n = len(content)
    while pos + 8 <= n:
        (length,) = struct.unpack(">I", content[pos : pos + 4])
        ctype = content[pos + 4 : pos + 8].decode("ascii", errors="replace")
        start = pos + 8
        end = start + length
        if length < 0 or end + 4 > n:
            break
        chunks.append((ctype, content[start:end]))
        pos = end + 4
    return chunks


def _png_text_severity(keyword: str) -> str:
    return "medium" if keyword.lower() in _PNG_TEXT_PERSON_KEYWORDS else "low"


def _parse_itxt(data: bytes) -> tuple[str, str] | None:
    keyword, sep, rest = data.partition(b"\x00")
    if not sep or len(rest) < 2:
        return None
    compression_flag = rest[0]
    remainder = rest[2:]
    _lang, sep, remainder = remainder.partition(b"\x00")
    if not sep:
        return None
    _translated, sep, text_bytes = remainder.partition(b"\x00")
    if not sep:
        return None
    if compression_flag:
        try:
            text_bytes = zlib.decompress(text_bytes)
        except zlib.error:
            return None
    return keyword.decode("latin-1", errors="replace"), text_bytes.decode("utf-8", errors="replace")


def _extract_png_fields(content: bytes) -> list[BinaryField]:
    fields: list[BinaryField] = []
    for ctype, data in _iter_png_chunks(content):
        if ctype == "tEXt":
            keyword, sep, value = data.partition(b"\x00")
            if not sep:
                continue
            keyword_s = keyword.decode("latin-1", errors="replace")
            text = value.decode("latin-1", errors="replace")
            if text:
                severity = _png_text_severity(keyword_s)
                fields.append(BinaryField(keyword_s, text, "png-text", severity))
        elif ctype == "zTXt":
            keyword, sep, rest = data.partition(b"\x00")
            if not sep or not rest:
                continue
            try:
                text = zlib.decompress(rest[1:]).decode("latin-1", errors="replace")
            except zlib.error:
                continue
            keyword_s = keyword.decode("latin-1", errors="replace")
            if text:
                severity = _png_text_severity(keyword_s)
                fields.append(BinaryField(keyword_s, text, "png-text", severity))
        elif ctype == "iTXt":
            parsed = _parse_itxt(data)
            if parsed and parsed[1]:
                fields.append(
                    BinaryField(parsed[0], parsed[1], "png-text", _png_text_severity(parsed[0]))
                )
        elif ctype == "tIME" and len(data) == 7:
            year, month, day, hour, minute, second = struct.unpack(">HBBBBB", data)
            time_text = f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
            fields.append(BinaryField("Time", time_text, "png-time", "low"))
        elif ctype == "eXIf":
            fields.extend(_png_embedded_exif(data))
    return fields


def _png_embedded_exif(data: bytes) -> list[BinaryField]:
    """architecture.md's rule ids give the PNG-embedded case one id, `png-exif`, not
    the three-way JPEG/TIFF/WebP split — GPS is the one exception: it is still "GPS in
    an image" (Default Severities) regardless of container, so it keeps `exif-gps`.
    """
    try:
        exif = Image.Exif()
        exif.load(data)
    except Exception:  # noqa: BLE001 - malformed eXIf chunk, not a reason to crash
        return []
    fields = _exif_fields(exif)
    return [
        f if f.rule_id == "exif-gps" else BinaryField(f.name, f.value, "png-exif", "medium")
        for f in fields
    ]


# -- PDF (pypdf) ---------------------------------------------------------------------

_PDF_PERSON_KEYS = frozenset({"author"})


def _extract_pdf_fields(content: bytes) -> list[BinaryField]:
    fields: list[BinaryField] = []
    try:
        reader = PdfReader(io.BytesIO(content))
        info = reader.metadata
    except Exception:  # noqa: BLE001 - not a PDF pypdf can parse
        return fields
    if info:
        for key, value in info.items():
            name = str(key).lstrip("/")
            text = str(value).strip() if value is not None else ""
            if not text:
                continue
            severity = "medium" if name.lower() in _PDF_PERSON_KEYS else "low"
            fields.append(BinaryField(name, text, "pdf-info", severity))
    try:
        xmp = reader.xmp_metadata
    except Exception:  # noqa: BLE001 - malformed XMP packet
        xmp = None
    if xmp is not None:
        fields.extend(_pdf_xmp_fields(xmp))
    return fields


_PDF_XMP_LOW_PROPS: tuple[tuple[str, str], ...] = (
    ("dc_title", "dc:title"),
    ("pdf_producer", "pdf:Producer"),
    ("xmp_creator_tool", "xmp:CreatorTool"),
)


def _pdf_xmp_fields(xmp: Any) -> list[BinaryField]:
    fields: list[BinaryField] = []
    try:
        creators = xmp.dc_creator
    except Exception:  # noqa: BLE001 - pypdf raises on a malformed rdf:Seq
        creators = None
    if creators:
        text = ", ".join(str(c) for c in creators if c)
        if text:
            fields.append(BinaryField("dc:creator", text, "pdf-xmp", "medium"))
    for attr, name in _PDF_XMP_LOW_PROPS:
        try:
            value = getattr(xmp, attr, None)
        except Exception:  # noqa: BLE001
            value = None
        if value:
            fields.append(BinaryField(name, str(value), "pdf-xmp", "low"))
    return fields


# -- OOXML (defusedxml; namespace-agnostic by matching on local tag/attribute names,
# since docx/xlsx/pptx all reuse the same docProps parts) ---------------------------


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _indexed_name(base: str, index: int) -> str:
    return base if index == 0 else f"{base}[{index}]"


def _parse_xml_part(data: bytes) -> Element | None:
    try:
        return ET.fromstring(data)  # type: ignore[no-any-return]
    except Exception:  # noqa: BLE001 - malformed part, not a reason to crash
        return None


def _extract_core_fields(data: bytes) -> list[BinaryField]:
    root = _parse_xml_part(data)
    if root is None:
        return []
    fields = []
    for el in root.iter():
        local = _local(el.tag)
        text = (el.text or "").strip()
        if local == "creator" and text:
            fields.append(BinaryField("creator", text, "ooxml-core", "medium"))
        elif local == "lastModifiedBy" and text:
            fields.append(BinaryField("lastModifiedBy", text, "ooxml-core", "medium"))
    return fields


def _extract_app_fields(data: bytes) -> list[BinaryField]:
    root = _parse_xml_part(data)
    if root is None:
        return []
    fields = []
    for el in root.iter():
        local = _local(el.tag)
        text = (el.text or "").strip()
        if local in ("Company", "Manager") and text:
            fields.append(BinaryField(local, text, "ooxml-app", "medium"))
    return fields


def _extract_custom_fields(data: bytes) -> list[BinaryField]:
    root = _parse_xml_part(data)
    if root is None:
        return []
    fields = []
    for el in root.iter():
        if _local(el.tag) != "property":
            continue
        name = el.get("name", "")
        text = ""
        for child in el:
            if child.text and child.text.strip():
                text = child.text.strip()
                break
        if name and text:
            fields.append(BinaryField(f"custom:{name}", text, "ooxml-custom", "medium"))
    return fields


def _extract_comment_authors(data: bytes) -> list[BinaryField]:
    root = _parse_xml_part(data)
    if root is None:
        return []
    fields = []
    index = 0
    for el in root.iter():
        if _local(el.tag) != "comment":
            continue
        author = next((v for k, v in el.attrib.items() if _local(k) == "author"), "")
        if author:
            name = _indexed_name("author", index)
            fields.append(BinaryField(name, author, "ooxml-comment-author", "medium"))
            index += 1
    return fields


def _extract_revision_authors(data: bytes) -> list[BinaryField]:
    root = _parse_xml_part(data)
    if root is None:
        return []
    fields = []
    index = 0
    for el in root.iter():
        if _local(el.tag) not in ("ins", "del"):
            continue
        author = next((v for k, v in el.attrib.items() if _local(k) == "author"), "")
        if author:
            name = _indexed_name("author", index)
            fields.append(BinaryField(name, author, "ooxml-revision-author", "medium"))
            index += 1
    return fields


_OOXML_PART_EXTRACTORS: tuple[tuple[str, Callable[[bytes], list[BinaryField]]], ...] = (
    ("docProps/core.xml", _extract_core_fields),
    ("docProps/app.xml", _extract_app_fields),
    ("docProps/custom.xml", _extract_custom_fields),
    ("word/comments.xml", _extract_comment_authors),
    ("word/document.xml", _extract_revision_authors),
)


def _extract_ooxml_fields(content: bytes) -> list[BinaryField]:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = set(archive.namelist())
            fields: list[BinaryField] = []
            for part_name, extractor in _OOXML_PART_EXTRACTORS:
                if part_name in names:
                    fields.extend(extractor(archive.read(part_name)))
            return fields
    except (zipfile.BadZipFile, OSError, NotImplementedError, ValueError):
        return []


_EXTRACTORS: dict[str, Callable[[bytes], list[BinaryField]]] = {
    "jpeg": _extract_image_exif,
    "tiff": _extract_image_exif,
    "webp": _extract_image_exif,
    "png": _extract_png_fields,
    "pdf": _extract_pdf_fields,
    "ooxml": _extract_ooxml_fields,
}


def extract_fields(kind: str, content: bytes) -> list[BinaryField]:
    """Extract every named field this blob's `kind` (a `detect.base.BINARY_KINDS`
    value) carries. Unknown kinds and malformed content both yield an empty list."""
    extractor = _EXTRACTORS.get(kind)
    if extractor is None:
        return []
    return extractor(content)
