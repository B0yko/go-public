"""Lossless in-place metadata stripping (product spec item 16; stage-5.md).

`strip_bytes`/`describe` dispatch on magic bytes (`detect.base.route_blob`) to one of
five format-specific strippers, each written to remove exactly the fields product
spec item 16 names and nothing else:

- JPEG: drops APP1 (EXIF/XMP), APP13 (Photoshop IRB/IPTC) and COM segments wherever
  they sit before EOI, without touching any other byte; every entropy-coded scan (all
  of them, for a progressive file) and anything after EOI is copied through untouched,
  so scan data and decoded pixels stay byte-identical. When the dropped EXIF held a
  non-default `Orientation`, a minimal replacement APP1 carrying only that one tag is
  written back so the image does not display rotated.
- PNG: drops `tEXt`/`zTXt`/`iTXt`/`tIME`/`eXIf` chunks whole (length+type+data+CRC);
  every other chunk, including every `IDAT`, is copied byte-for-byte.
- WebP: drops the `EXIF`/`XMP ` RIFF chunks and rewrites the `VP8X` flags byte and the
  RIFF container size to match; every other chunk (image data, alpha, animation) is
  untouched.
- PDF: clears the Info dictionary and the XMP metadata stream via `pypdf` on a clone of
  the whole document (embedded files, forms and outlines survive); no byte-identity
  requirement here: PDF is not a lossy media format the way a JPEG scan is.
- OOXML: blanks the person/organisation fields `detect/binary_meta.py` extracts from
  `docProps/core.xml` (`creator`, `lastModifiedBy`) and `docProps/app.xml` (`Company`,
  `Manager`); every other zip entry, including comments and tracked changes, is left
  alone — "Tracked changes and comments are reported, never auto-removed" is item 16's
  own wording, and `plan.py`'s `STRIP_EXCLUDED_RULE_IDS` matches this.

Every stripper is defensive: content its own format's magic bytes matched but that it
otherwise cannot parse is returned unchanged rather than raising, the same defensive
posture `detect/binary_meta.py` already takes for extraction.

`export/squash.py` calls `strip_bytes` in memory on every kept blob (when metadata
stripping is on); `cli.py`'s `strip` command calls it on real files, and `describe`
for `--check`.
"""

from __future__ import annotations

import io
import struct
import xml.etree.ElementTree as ET_write
import zipfile

import defusedxml.ElementTree as ET_read
from PIL import Image
from PIL.ExifTags import Base as ExifTag
from pypdf import PdfReader, PdfWriter

from go_public.detect.base import route_blob
from go_public.detect.binary_meta import extract_fields

#: Routing content this large would only matter for the plain-text/"large" split
#: (`detect.base.route_blob`'s `max_scan_mb` gate); none of the binary formats below
#: are gated by size at all, so a generous constant keeps every call site simple.
_NO_SIZE_GATE_MB = 10**6

# -- JPEG -----------------------------------------------------------------------------

_JPEG_SOI = b"\xff\xd8"
_MARKER_SOS = 0xDA
_MARKER_EOI = 0xD9
_MARKER_APP1 = 0xE1
_MARKER_APP13 = 0xED
_MARKER_COM = 0xFE
#: Markers with no length-prefixed payload: TEM (0x01), RSTn (0xD0-0xD7), SOI/EOI.
_JPEG_NO_PAYLOAD_MARKERS = frozenset({0x01, *range(0xD0, 0xD8)})
_ORIENTATION_TAG = ExifTag.Orientation.value


def _jpeg_orientation(data: bytes) -> int | None:
    try:
        with Image.open(io.BytesIO(data)) as img:
            value = img.getexif().get(_ORIENTATION_TAG)
    except Exception:  # noqa: BLE001 - not a JPEG Pillow can open
        return None
    return int(value) if isinstance(value, int) else None


def _minimal_orientation_app1(orientation: int) -> bytes:
    """A from-scratch APP1/EXIF segment whose only IFD0 entry is `Orientation`."""
    tiff_header = b"II" + struct.pack("<HI", 42, 8)
    value_field = struct.pack("<H", orientation) + b"\x00\x00"
    entry = struct.pack("<HHI", _ORIENTATION_TAG, 3, 1) + value_field
    ifd0 = struct.pack("<H", 1) + entry + struct.pack("<I", 0)
    payload = b"Exif\x00\x00" + tiff_header + ifd0
    return struct.pack(">BBH", 0xFF, _MARKER_APP1, len(payload) + 2) + payload


_RAW = -1  # marker value for bytes that are not a marker segment (passed through)
_RST_RANGE = range(0xD0, 0xD8)


def _next_marker_start(data: bytes, start: int, *, in_scan: bool) -> int:
    """Offset of the next marker prefix at or after `start` (`len(data)` if none). A
    stuffed `FF 00` is never a marker; inside entropy-coded data neither is `FF Dn`."""
    n = len(data)
    pos = start
    while True:
        pos = data.find(b"\xff", pos)
        if pos < 0 or pos + 1 >= n:
            return n
        following = data[pos + 1]
        if following == 0x00 or (in_scan and following in _RST_RANGE):
            pos += 2
            continue
        return pos


def _iter_jpeg_segments(data: bytes) -> list[tuple[int, int, int]]:
    """`[(marker, start, end), ...]` for the whole stream from after SOI up to and
    including EOI. A span covers the marker's own bytes (fill bytes included) and its
    payload; an SOS span also covers its entropy-coded data. Bytes that are not part of
    a marker segment (extraneous bytes decoders skip) are `_RAW` spans. Malformed or
    truncated input stops early; the caller copies whatever follows the last span."""
    segments: list[tuple[int, int, int]] = []
    pos = 2  # past the two-byte SOI
    n = len(data)
    while pos < n:
        if data[pos] != 0xFF or (pos + 1 < n and data[pos + 1] == 0x00):
            end = _next_marker_start(data, pos + (1 if data[pos] != 0xFF else 2), in_scan=False)
            segments.append((_RAW, pos, end))
            pos = end
            continue
        marker_pos = pos
        while marker_pos < n and data[marker_pos] == 0xFF:
            marker_pos += 1
        if marker_pos >= n:
            break
        marker = data[marker_pos]
        after_marker = marker_pos + 1
        if marker == 0x00:
            segments.append((_RAW, pos, after_marker))
            pos = after_marker
            continue
        if marker == _MARKER_EOI:
            segments.append((marker, pos, after_marker))
            break
        if marker in _JPEG_NO_PAYLOAD_MARKERS:
            segments.append((marker, pos, after_marker))
            pos = after_marker
            continue
        if after_marker + 2 > n:
            break
        (seg_len,) = struct.unpack(">H", data[after_marker : after_marker + 2])
        seg_end = after_marker + seg_len
        if seg_len < 2 or seg_end > n:
            break
        if marker == _MARKER_SOS:
            seg_end = _next_marker_start(data, seg_end, in_scan=True)
        segments.append((marker, pos, seg_end))
        pos = seg_end
    return segments


_JPEG_DROPPED_MARKERS = {
    _MARKER_APP1: "APP1 (EXIF/XMP)",
    _MARKER_APP13: "APP13 (Photoshop IRB/IPTC)",
    _MARKER_COM: "COM (comment)",
}


def strip_jpeg(data: bytes) -> bytes:
    """Drop APP1, APP13 and COM segments wherever they sit before EOI (progressive files
    may carry a COM between scans); every other byte, entropy-coded scan data included,
    is copied through untouched, as is anything after EOI."""
    if not data.startswith(_JPEG_SOI):
        return data
    orientation = _jpeg_orientation(data)
    out = bytearray(_JPEG_SOI)
    if orientation is not None and orientation != 1:
        out += _minimal_orientation_app1(orientation)
    last_end = 2
    for marker, seg_start, seg_end in _iter_jpeg_segments(data):
        if marker not in _JPEG_DROPPED_MARKERS:
            out += data[seg_start:seg_end]
        last_end = seg_end
    out += data[last_end:]
    return bytes(out)


def _jpeg_droppable(data: bytes) -> list[str]:
    if not data.startswith(_JPEG_SOI) or strip_jpeg(data) == data:
        return []
    return [
        _JPEG_DROPPED_MARKERS[marker]
        for marker, _start, _end in _iter_jpeg_segments(data)
        if marker in _JPEG_DROPPED_MARKERS
    ]


# -- PNG ------------------------------------------------------------------------------

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_DROPPED_TYPES = frozenset({"tEXt", "zTXt", "iTXt", "tIME", "eXIf"})


def _iter_png_chunks(data: bytes) -> list[tuple[str, int, int]]:
    """`[(chunk_type, chunk_start, chunk_end), ...]`; each span covers the whole
    length+type+data+CRC record, so copying `data[start:end]` reproduces the chunk
    byte-for-byte."""
    chunks: list[tuple[str, int, int]] = []
    pos = len(_PNG_SIGNATURE)
    n = len(data)
    while pos + 8 <= n:
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        ctype = data[pos + 4 : pos + 8].decode("ascii", errors="replace")
        chunk_end = pos + 8 + length + 4
        if chunk_end > n:
            break
        chunks.append((ctype, pos, chunk_end))
        pos = chunk_end
        if ctype == "IEND":
            break
    return chunks


def strip_png(data: bytes) -> bytes:
    if not data.startswith(_PNG_SIGNATURE):
        return data
    chunks = _iter_png_chunks(data)
    out = bytearray(_PNG_SIGNATURE)
    last_end = len(_PNG_SIGNATURE)
    for ctype, start, end in chunks:
        if ctype not in _PNG_DROPPED_TYPES:
            out += data[start:end]
        last_end = end
    out += data[last_end:]  # any trailing bytes after IEND, preserved verbatim
    return bytes(out)


def _png_droppable(data: bytes) -> list[str]:
    if not data.startswith(_PNG_SIGNATURE):
        return []
    return [
        f"PNG {ctype} chunk"
        for ctype, _start, _end in _iter_png_chunks(data)
        if ctype in _PNG_DROPPED_TYPES
    ]


# -- WebP -----------------------------------------------------------------------------

_RIFF_TAG = b"RIFF"
_WEBP_TAG = b"WEBP"
_WEBP_DROPPED_FOURCCS = frozenset({b"EXIF", b"XMP "})
_VP8X_FOURCC = b"VP8X"
_VP8X_EXIF_XMP_FLAGS = 0x08 | 0x04  # Exif (bit 3) and XMP (bit 2)


def _parse_webp(data: bytes) -> tuple[list[tuple[bytes, bytes]], bytes] | None:
    """`([(fourcc, chunk_data), ...], leftover)` (padding byte, if any, excluded;
    `leftover` is whatever a truncated or malformed tail leaves unparsed), or `None`
    when `data` is not a RIFF/WEBP container at all."""
    if data[:4] != _RIFF_TAG or data[8:12] != _WEBP_TAG:
        return None
    chunks: list[tuple[bytes, bytes]] = []
    pos = 12
    n = len(data)
    while pos + 8 <= n:
        fourcc = data[pos : pos + 4]
        (size,) = struct.unpack("<I", data[pos + 4 : pos + 8])
        data_start = pos + 8
        data_end = data_start + size
        if data_end > n:
            break
        chunks.append((fourcc, data[data_start:data_end]))
        pos = data_end + (size % 2)
    return chunks, data[min(pos, n) :]


def _iter_webp_chunks(data: bytes) -> list[tuple[bytes, bytes]] | None:
    parsed = _parse_webp(data)
    return None if parsed is None else parsed[0]


def _build_webp(chunks: list[tuple[bytes, bytes]], leftover: bytes = b"") -> bytes:
    body = bytearray()
    for fourcc, chunk_data in chunks:
        body += fourcc
        body += struct.pack("<I", len(chunk_data))
        body += chunk_data
        if len(chunk_data) % 2:
            body += b"\x00"
    body += leftover  # a truncated tail is kept, not silently cut off
    out = bytearray(_RIFF_TAG)
    out += struct.pack("<I", 4 + len(body))  # "WEBP" + every remaining chunk
    out += _WEBP_TAG
    out += body
    return bytes(out)


def strip_webp(data: bytes) -> bytes:
    parsed = _parse_webp(data)
    if parsed is None:
        return data
    chunks, leftover = parsed
    if leftover[:4] in _WEBP_DROPPED_FOURCCS:
        leftover = b""  # a truncated EXIF/XMP chunk is metadata all the same
    kept: list[tuple[bytes, bytes]] = []
    for fourcc, chunk_data in chunks:
        if fourcc in _WEBP_DROPPED_FOURCCS:
            continue
        if fourcc == _VP8X_FOURCC and chunk_data:
            chunk_data = bytes([chunk_data[0] & ~_VP8X_EXIF_XMP_FLAGS]) + chunk_data[1:]
        kept.append((fourcc, chunk_data))
    return _build_webp(kept, leftover)


_WEBP_DROPPABLE_NAMES = {b"EXIF": "WebP EXIF chunk", b"XMP ": "WebP XMP chunk"}


def _webp_droppable(data: bytes) -> list[str]:
    chunks = _iter_webp_chunks(data)
    if chunks is None:
        return []
    return [
        _WEBP_DROPPABLE_NAMES[fourcc] for fourcc, _data in chunks if fourcc in _WEBP_DROPPABLE_NAMES
    ]


# -- PDF (pypdf; no byte-identity requirement) -----------------------------------------


def strip_pdf(data: bytes) -> bytes:
    try:
        reader = PdfReader(io.BytesIO(data))
        # clone_from keeps the whole catalog (embedded files, forms, outlines, names);
        # `append` would rebuild it from the pages alone and drop those.
        writer = PdfWriter(clone_from=reader)
        writer.metadata = None  # clears the whole Info dictionary
        writer.xmp_metadata = None  # drops the /Metadata XMP stream, if any
        out = io.BytesIO()
        writer.write(out)
    except Exception:  # noqa: BLE001 - not a PDF pypdf can parse or rewrite
        return data
    return out.getvalue()


def _pdf_droppable(data: bytes) -> list[str]:
    found = []
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.metadata:
            found.append("PDF Info dictionary")
    except Exception:  # noqa: BLE001 - a PDF pypdf cannot read has nothing to strip
        return []
    try:
        if reader.xmp_metadata is not None:
            found.append("PDF XMP metadata")
    except Exception:  # noqa: BLE001 - malformed XMP packet
        pass
    return found


# -- OOXML (defusedxml to parse, stdlib ElementTree to re-serialise what we built) ----

_CORE_PART = "docProps/core.xml"
_APP_PART = "docProps/app.xml"
_CORE_PERSON_LOCAL_NAMES = frozenset({"creator", "lastModifiedBy"})
_APP_ORG_LOCAL_NAMES = frozenset({"Company", "Manager"})

for _prefix, _uri in (
    ("cp", "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"),
    ("dc", "http://purl.org/dc/elements/1.1/"),
    ("dcterms", "http://purl.org/dc/terms/"),
    ("xsi", "http://www.w3.org/2001/XMLSchema-instance"),
    ("vt", "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"),
    ("", "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"),
):
    ET_write.register_namespace(_prefix, _uri)


#: Findings `strip` reports but never removes (mirrors `plan.STRIP_EXCLUDED_RULE_IDS`).
_REPORT_ONLY_RULE_IDS = frozenset({"ooxml-comment-author", "ooxml-revision-author", "ooxml-custom"})


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _blank_local_names(data: bytes, local_names: frozenset[str]) -> bytes:
    try:
        root: ET_write.Element = ET_read.fromstring(data)
    except Exception:  # noqa: BLE001 - malformed part, leave untouched
        return data
    changed = False
    for el in root.iter():
        if _local(el.tag) in local_names and (el.text or "").strip():
            el.text = ""
            changed = True
    if not changed:
        return data
    serialised: bytes = ET_write.tostring(root, encoding="UTF-8", xml_declaration=True)
    return serialised


def strip_ooxml(content: bytes) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as src:
            infos = src.infolist()
            data_by_name = {info.filename: src.read(info.filename) for info in infos}
    except Exception:  # noqa: BLE001 - corrupt or encrypted entries: leave it as it is
        return content
    if _CORE_PART in data_by_name:
        core = data_by_name[_CORE_PART]
        data_by_name[_CORE_PART] = _blank_local_names(core, _CORE_PERSON_LOCAL_NAMES)
    if _APP_PART in data_by_name:
        app = data_by_name[_APP_PART]
        data_by_name[_APP_PART] = _blank_local_names(app, _APP_ORG_LOCAL_NAMES)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in infos:
            dst.writestr(info, data_by_name[info.filename])
    return out.getvalue()


def _ooxml_droppable(data: bytes) -> list[str]:
    found = []
    try:
        fields = extract_fields("ooxml", data)
    except Exception:  # noqa: BLE001 - corrupt archive: nothing strip could remove
        return []
    for field in fields:
        if field.rule_id == "ooxml-core" and field.name in _CORE_PERSON_LOCAL_NAMES:
            found.append(f"{_CORE_PART} {field.name}")
        elif field.rule_id == "ooxml-app" and field.name in _APP_ORG_LOCAL_NAMES:
            found.append(f"{_APP_PART} {field.name}")
    return found


# -- dispatch ---------------------------------------------------------------------------

_STRIPPERS = {
    "jpeg": strip_jpeg,
    "tiff": lambda data: data,  # TIFF EXIF stripping is not named by item 16; left as-is
    "png": strip_png,
    "webp": strip_webp,
    "pdf": strip_pdf,
    "ooxml": strip_ooxml,
}

_DESCRIBERS = {
    "jpeg": _jpeg_droppable,
    "png": _png_droppable,
    "webp": _webp_droppable,
    "pdf": _pdf_droppable,
    "ooxml": _ooxml_droppable,
}


def strip_bytes(content: bytes) -> bytes:
    """`content` with every metadata field product spec item 16 names removed, or
    `content` unchanged when its format carries none of them (text, an archive that
    is not OOXML, or a binary kind stripping does not touch)."""
    kind = route_blob(content, max_scan_mb=_NO_SIZE_GATE_MB).kind
    stripper = _STRIPPERS.get(kind)
    return stripper(content) if stripper else content


def describe(content: bytes) -> list[str]:
    """Human-readable names of what `strip_bytes` would remove from `content`, or an
    empty list when there is nothing to remove (`go-public strip --check`)."""
    kind = route_blob(content, max_scan_mb=_NO_SIZE_GATE_MB).kind
    describer = _DESCRIBERS.get(kind)
    return describer(content) if describer else []


def residual_fields(content: bytes) -> set[tuple[str, str]]:
    """`(rule_id, field name)` of every binary-metadata field that survives
    `strip_bytes(content)`: what the export would still ship."""
    stripped = strip_bytes(content)
    kind = route_blob(stripped, max_scan_mb=_NO_SIZE_GATE_MB).kind
    return {(field.rule_id, field.name) for field in extract_fields(kind, stripped)}


def reported_only(content: bytes) -> list[str]:
    """What `content` carries that `strip` reports but never removes (product spec item
    16: OOXML tracked changes and comments)."""
    kind = route_blob(content, max_scan_mb=_NO_SIZE_GATE_MB).kind
    if kind != "ooxml":
        return []
    return sorted(
        {
            f"{field.name} ({field.rule_id})"
            for field in extract_fields("ooxml", content)
            if field.rule_id in _REPORT_ONLY_RULE_IDS
        }
    )
