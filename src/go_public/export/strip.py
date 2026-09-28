"""Lossless in-place metadata stripping (product spec item 16; stage-5.md).

`strip_bytes`/`describe` dispatch on magic bytes (`detect.base.route_blob`) to one of
five format-specific strippers, each written to remove exactly the fields product
spec item 16 names and nothing else:

- JPEG: drops APP1 (EXIF/XMP), APP13 (Photoshop IRB/IPTC) and COM segments without
  touching any other byte; the entropy-coded scan data (everything from the first SOS
  marker to EOI) is copied through untouched, so it and the decoded pixels stay
  byte-identical. When the dropped EXIF held a non-default `Orientation`, a minimal
  replacement APP1 carrying only that one tag is written back so the image does not
  display rotated.
- PNG: drops `tEXt`/`zTXt`/`iTXt`/`tIME`/`eXIf` chunks whole (length+type+data+CRC);
  every other chunk, including every `IDAT`, is copied byte-for-byte.
- WebP: drops the `EXIF`/`XMP ` RIFF chunks and rewrites the `VP8X` flags byte and the
  RIFF container size to match; every other chunk (image data, alpha, animation) is
  untouched.
- PDF: clears the Info dictionary and the XMP metadata stream via `pypdf` (no
  byte-identity requirement here: PDF is not a lossy media format the way a JPEG scan
  is).
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


def _iter_jpeg_head_segments(data: bytes) -> list[tuple[int, int, int]]:
    """`[(marker, seg_start, seg_end), ...]` for every segment before the first SOS
    (or EOI, for a scan-less file). `seg_start`/`seg_end` span the marker's own two
    bytes through the end of its payload (or just the two marker bytes, for a
    no-payload marker); malformed/truncated input simply stops early.
    """
    segments: list[tuple[int, int, int]] = []
    pos = 2  # past the two-byte SOI
    n = len(data)
    while pos < n:
        if data[pos] != 0xFF:
            break
        marker_pos = pos
        while marker_pos < n and data[marker_pos] == 0xFF:
            marker_pos += 1
        if marker_pos >= n:
            break
        marker = data[marker_pos]
        seg_start = pos
        after_marker = marker_pos + 1
        if marker in _JPEG_NO_PAYLOAD_MARKERS:
            segments.append((marker, seg_start, after_marker))
            pos = after_marker
            continue
        if marker in (_MARKER_EOI, _MARKER_SOS):
            segments.append((marker, seg_start, after_marker))
            break
        if after_marker + 2 > n:
            break
        (seg_len,) = struct.unpack(">H", data[after_marker : after_marker + 2])
        seg_end = after_marker + seg_len
        if seg_end > n:
            break
        segments.append((marker, seg_start, seg_end))
        pos = seg_end
    return segments


_JPEG_DROPPED_MARKERS = {
    _MARKER_APP1: "APP1 (EXIF/XMP)",
    _MARKER_APP13: "APP13 (Photoshop IRB/IPTC)",
    _MARKER_COM: "COM (comment)",
}


def strip_jpeg(data: bytes) -> bytes:
    if not data.startswith(_JPEG_SOI):
        return data
    orientation = _jpeg_orientation(data)
    segments = _iter_jpeg_head_segments(data)

    out = bytearray(_JPEG_SOI)
    if orientation is not None and orientation != 1:
        out += _minimal_orientation_app1(orientation)

    last_end = 2
    sos_or_eoi_at: int | None = None
    for marker, seg_start, seg_end in segments:
        if marker in (_MARKER_SOS, _MARKER_EOI):
            sos_or_eoi_at = seg_start
            break
        if marker not in _JPEG_DROPPED_MARKERS:
            out += data[seg_start:seg_end]
        last_end = seg_end

    # Everything from the first SOS (its length-prefixed header plus every byte of
    # entropy-coded scan data through EOI) — or, for a scan-less/malformed file,
    # whatever is left — is copied through untouched: never re-encoded, never
    # re-parsed, so it and the decoded pixels stay byte-identical.
    tail_start = sos_or_eoi_at if sos_or_eoi_at is not None else last_end
    out += data[tail_start:]
    return bytes(out)


def _jpeg_droppable(data: bytes) -> list[str]:
    if not data.startswith(_JPEG_SOI):
        return []
    return [
        _JPEG_DROPPED_MARKERS[marker]
        for marker, _start, _end in _iter_jpeg_head_segments(data)
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


def _iter_webp_chunks(data: bytes) -> list[tuple[bytes, bytes]] | None:
    """`[(fourcc, chunk_data), ...]` (padding byte, if any, excluded), or `None` when
    `data` is not a RIFF/WEBP container at all."""
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
    return chunks


def _build_webp(chunks: list[tuple[bytes, bytes]]) -> bytes:
    body = bytearray()
    for fourcc, chunk_data in chunks:
        body += fourcc
        body += struct.pack("<I", len(chunk_data))
        body += chunk_data
        if len(chunk_data) % 2:
            body += b"\x00"
    out = bytearray(_RIFF_TAG)
    out += struct.pack("<I", 4 + len(body))  # "WEBP" + every remaining chunk
    out += _WEBP_TAG
    out += body
    return bytes(out)


def strip_webp(data: bytes) -> bytes:
    chunks = _iter_webp_chunks(data)
    if chunks is None:
        return data
    kept: list[tuple[bytes, bytes]] = []
    for fourcc, chunk_data in chunks:
        if fourcc in _WEBP_DROPPED_FOURCCS:
            continue
        if fourcc == _VP8X_FOURCC and chunk_data:
            chunk_data = bytes([chunk_data[0] & ~_VP8X_EXIF_XMP_FLAGS]) + chunk_data[1:]
        kept.append((fourcc, chunk_data))
    return _build_webp(kept)


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
        writer = PdfWriter()
        writer.append(reader)
    except Exception:  # noqa: BLE001 - not a PDF pypdf can parse
        return data
    writer.metadata = None  # clears the whole Info dictionary
    writer.xmp_metadata = None  # drops the /Metadata XMP stream, if any
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def _pdf_droppable(data: bytes) -> list[str]:
    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        return []
    found = []
    if reader.metadata:
        found.append("PDF Info dictionary")
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
    except (zipfile.BadZipFile, OSError, NotImplementedError, ValueError):
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
    for field in extract_fields("ooxml", data):
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
