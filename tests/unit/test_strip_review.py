"""Stage 5r: adversarial inputs for `export/strip.py` (lossy or leaky strips)."""

from __future__ import annotations

import io
import struct
import zipfile

from PIL import Image
from PIL.ExifTags import Base as ExifTag
from pypdf import PdfReader, PdfWriter

from go_public.bench import binaries
from go_public.detect.binary_meta import extract_fields
from go_public.export import strip

PERSON = "Zed Secretperson"


def _progressive_jpeg(exif: Image.Exif | None = None) -> bytes:
    img = Image.new("RGB", (64, 64))
    for x in range(64):
        for y in range(64):
            img.putpixel((x, y), (x * 4 % 256, y * 4 % 256, x * y % 256))
    buf = io.BytesIO()
    kwargs = {"exif": exif} if exif is not None else {}
    img.save(buf, format="JPEG", progressive=True, quality=80, **kwargs)
    return buf.getvalue()


def _segment(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload


def _scan_bytes(data: bytes) -> list[bytes]:
    """Every SOS header plus its entropy-coded data, in order."""
    spans = []
    for marker, start, end in strip._iter_jpeg_segments(data):
        if marker == strip._MARKER_SOS:
            spans.append(data[start:end])
    return spans


def _pixels(data: bytes) -> bytes:
    with Image.open(io.BytesIO(data)) as img:
        return img.convert("RGB").tobytes()


def test_jpeg_comment_between_progressive_scans_is_dropped_and_scans_stay_identical() -> None:
    original = _progressive_jpeg()
    second_scan = [s for m, s, _e in strip._iter_jpeg_segments(original) if m == 0xDA][1]
    dirty = original[:second_scan] + _segment(0xFE, PERSON.encode()) + original[second_scan:]

    stripped = strip.strip_jpeg(dirty)

    assert PERSON.encode() not in stripped
    assert stripped == original
    assert _scan_bytes(stripped) == _scan_bytes(dirty)
    assert _pixels(stripped) == _pixels(dirty)


def test_jpeg_exif_after_extraneous_bytes_is_still_dropped() -> None:
    clean = binaries.jpeg_with_field(ExifTag.Artist.value, PERSON)
    at = clean.index(b"\xff\xe1")
    dirty = clean[:at] + b"\x00\x12" + clean[at:]
    assert [f.name for f in extract_fields("jpeg", dirty)] == ["Artist"]

    stripped = strip.strip_jpeg(dirty)

    assert extract_fields("jpeg", stripped) == []
    assert PERSON.encode() not in stripped
    assert _pixels(stripped) == _pixels(dirty)


def test_jpeg_with_non_default_orientation_is_clean_after_one_strip() -> None:
    exif = Image.Exif()
    exif[ExifTag.Orientation.value] = 6
    once = strip.strip_jpeg(_progressive_jpeg(exif))

    assert strip.strip_jpeg(once) == once
    assert strip.describe(once) == []


def test_jpeg_keeps_color_transform_and_icc_segments() -> None:
    clean = binaries.jpeg_with_field(ExifTag.Artist.value, PERSON)
    adobe = _segment(0xEE, b"Adobe\x00\x64\x00\x00\x00\x00\x00")
    icc = _segment(0xE2, b"ICC_PROFILE\x00\x01\x01" + b"\x00" * 8)
    dirty = clean[:2] + adobe + icc + clean[2:]

    stripped = strip.strip_jpeg(dirty)

    assert adobe in stripped
    assert icc in stripped
    assert PERSON.encode() not in stripped


def _webp_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    chunks = strip._iter_webp_chunks(data)
    assert chunks is not None
    return chunks


def test_truncated_webp_keeps_the_image_bytes_it_cannot_parse() -> None:
    original = binaries.webp_with_field(ExifTag.Artist.value, PERSON)
    chunks = dict(_webp_chunks(original))
    exif_first = strip._build_webp([(b"VP8X", chunks[b"VP8X"]), (b"EXIF", chunks[b"EXIF"])])
    dirty = exif_first + b"VP8 " + struct.pack("<I", 100) + chunks[b"VP8 "][:20]
    assert PERSON.encode() in dirty

    stripped = strip.strip_webp(dirty)

    assert PERSON.encode() not in stripped
    assert stripped.endswith(b"VP8 " + struct.pack("<I", 100) + chunks[b"VP8 "][:20])


def test_webp_truncated_inside_the_exif_chunk_drops_the_partial_metadata() -> None:
    original = binaries.webp_with_field(ExifTag.Artist.value, PERSON)

    stripped = strip.strip_webp(original[:-6])

    assert PERSON.encode()[:4] not in stripped
    assert b"EXIF" not in stripped


def _pdf_with_attachment_and_author() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    writer.add_blank_page(200, 200)
    writer.add_outline_item("Chapter", 1)
    writer.add_attachment("note.txt", b"attached payload")
    writer.add_metadata({"/Author": PERSON})
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def test_strip_pdf_keeps_embedded_files_and_outline() -> None:
    original = _pdf_with_attachment_and_author()

    stripped = strip.strip_pdf(original)

    reader = PdfReader(io.BytesIO(stripped))
    assert reader.attachments["note.txt"] == [b"attached payload"]
    assert len(reader.outline) == 1
    assert len(reader.pages) == 2
    assert reader.metadata is None
    assert PERSON.encode() not in stripped


def test_ooxml_custom_properties_are_reported_but_not_promised_as_strippable() -> None:
    from go_public.plan import is_strip_resolvable

    assert not is_strip_resolvable("ooxml-custom")
    assert "ooxml-custom" in strip._REPORT_ONLY_RULE_IDS


def _docx_with_corrupt_core_entry() -> bytes:
    data = bytearray(binaries.minimal_docx())
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as archive:
        info = archive.getinfo("docProps/core.xml")
    body = info.header_offset + 30 + len(info.filename) + len(info.extra)
    for i in range(body, body + 8):
        data[i] ^= 0xFF
    return bytes(data)


def test_corrupt_ooxml_entry_is_returned_unchanged_instead_of_raising() -> None:
    docx = _docx_with_corrupt_core_entry()

    assert strip.strip_bytes(docx) == docx
    assert strip.describe(docx) == []


def test_extracting_fields_from_a_corrupt_ooxml_entry_yields_nothing() -> None:
    assert extract_fields("ooxml", _docx_with_corrupt_core_entry()) == []


def test_damaged_pdf_is_returned_unchanged_instead_of_raising() -> None:
    pdf = _pdf_with_attachment_and_author()
    damaged = pdf[: len(pdf) // 2] + b"\x00" * 40 + pdf[len(pdf) // 2 + 40 :]

    assert strip.strip_bytes(damaged) is not None
    assert strip.describe(damaged) is not None
