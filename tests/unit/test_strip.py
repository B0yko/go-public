"""`export/strip.py`: lossless metadata stripping for JPEG/PNG/WebP/PDF/OOXML
(product spec item 16; stage-5.md).
"""

from __future__ import annotations

import io

from PIL import Image
from PIL.ExifTags import Base as ExifTag
from pypdf import PdfReader

from go_public.bench import binaries
from go_public.detect.binary_meta import extract_fields
from go_public.export import strip

# -- JPEG -------------------------------------------------------------------------


def _image_exif(data: bytes) -> Image.Exif:
    with Image.open(io.BytesIO(data)) as img:
        return img.getexif()


def _jpeg_pixels(data: bytes) -> bytes:
    with Image.open(io.BytesIO(data)) as img:
        return img.convert("RGB").tobytes()


def test_strip_jpeg_removes_exif_field() -> None:
    original = binaries.jpeg_with_field(ExifTag.Artist.value, "Person Name")
    stripped = strip.strip_jpeg(original)

    assert ExifTag.Artist.value not in _image_exif(stripped)
    assert stripped != original


def test_strip_jpeg_removes_gps() -> None:
    original = binaries.jpeg_with_gps(1.0, 2.0)
    stripped = strip.strip_jpeg(original)

    assert not _image_exif(stripped).get_ifd(0x8825)  # GPSInfo IFD pointer tag


def test_strip_jpeg_keeps_scan_data_and_pixels_byte_identical() -> None:
    original = binaries.jpeg_with_field(ExifTag.Artist.value, "Person Name")
    stripped = strip.strip_jpeg(original)

    orig_sos = original.index(b"\xff\xda")
    stripped_sos = stripped.index(b"\xff\xda")
    assert original[orig_sos:] == stripped[stripped_sos:]
    assert _jpeg_pixels(stripped) == _jpeg_pixels(original)


def test_strip_jpeg_with_no_metadata_is_unchanged() -> None:
    img = Image.new("RGB", (4, 4), color=(1, 2, 3))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    original = buf.getvalue()

    assert strip.strip_jpeg(original) == original


def test_strip_jpeg_preserves_non_default_orientation() -> None:
    exif = Image.Exif()
    exif[ExifTag.Artist.value] = "Person Name"
    exif[ExifTag.Orientation.value] = 6
    img = Image.new("RGB", (4, 4), color=(9, 9, 9))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    original = buf.getvalue()

    stripped = strip.strip_jpeg(original)

    stripped_exif = _image_exif(stripped)
    assert stripped_exif.get(ExifTag.Orientation.value) == 6
    assert ExifTag.Artist.value not in stripped_exif


def test_jpeg_droppable_lists_segments_present() -> None:
    original = binaries.jpeg_with_field(ExifTag.Artist.value, "Person Name")
    assert strip.describe(original) == ["APP1 (EXIF/XMP)"]
    assert strip.describe(strip.strip_jpeg(original)) == []


# -- PNG --------------------------------------------------------------------------


def _png_idat_chunks(data: bytes) -> list[bytes]:
    return [data[s:e] for ctype, s, e in strip._iter_png_chunks(data) if ctype == "IDAT"]


def test_strip_png_removes_text_chunk_keeps_idat_identical() -> None:
    original = binaries.png_with_text("Author", "Person Name")
    stripped = strip.strip_png(original)

    assert _png_idat_chunks(stripped) == _png_idat_chunks(original)
    assert not any(ctype == "tEXt" for ctype, _s, _e in strip._iter_png_chunks(stripped))


def test_strip_png_decoded_pixels_identical() -> None:
    original = binaries.png_with_text("Author", "Person Name")
    stripped = strip.strip_png(original)

    with Image.open(io.BytesIO(original)) as a, Image.open(io.BytesIO(stripped)) as b:
        assert a.tobytes() == b.tobytes()


def test_strip_png_removes_time_and_exif_chunks() -> None:
    time_png = binaries.png_with_time(2024, 1, 1, 0, 0, 0)
    exif_png = binaries.png_with_exif(ExifTag.Artist.value, "Person Name")

    assert not any(c == "tIME" for c, _s, _e in strip._iter_png_chunks(strip.strip_png(time_png)))
    assert not any(c == "eXIf" for c, _s, _e in strip._iter_png_chunks(strip.strip_png(exif_png)))


def test_png_droppable_lists_chunks_present() -> None:
    original = binaries.png_with_text("Author", "Person Name")
    assert strip.describe(original) == ["PNG tEXt chunk"]
    assert strip.describe(strip.strip_png(original)) == []


# -- WebP -------------------------------------------------------------------------


def test_strip_webp_removes_exif_and_decodes_identically() -> None:
    original = binaries.webp_with_field(ExifTag.Artist.value, "Person Name")
    stripped = strip.strip_webp(original)

    with Image.open(io.BytesIO(original)) as a, Image.open(io.BytesIO(stripped)) as b:
        assert a.convert("RGB").tobytes() == b.convert("RGB").tobytes()
    assert not _image_exif(stripped)  # getexif() also works for a Pillow-opened WebP


def test_strip_webp_riff_size_matches_remaining_bytes() -> None:
    import struct

    original = binaries.webp_with_field(ExifTag.Artist.value, "Person Name")
    stripped = strip.strip_webp(original)

    (riff_size,) = struct.unpack("<I", stripped[4:8])
    assert riff_size == len(stripped) - 8


def test_strip_webp_clears_the_vp8x_exif_and_xmp_flags() -> None:
    original = binaries.webp_with_field(ExifTag.Artist.value, "Person Name")
    assert original[12:16] == b"VP8X"
    assert original[20] & 0x08  # EXIF flag set before stripping

    stripped = strip.strip_webp(original)

    assert stripped[12:16] == b"VP8X"
    assert stripped[20] & 0x0C == 0  # EXIF (0x08) and XMP (0x04) flags cleared
    assert stripped[20] == original[20] & ~0x0C  # every other flag untouched


def test_webp_droppable_lists_chunks_present() -> None:
    original = binaries.webp_with_field(ExifTag.Artist.value, "Person Name")
    assert strip.describe(original) == ["WebP EXIF chunk"]
    assert strip.describe(strip.strip_webp(original)) == []


# -- PDF --------------------------------------------------------------------------


def test_strip_pdf_clears_info_dictionary() -> None:
    original = binaries.pdf_with_author("Person Name")
    stripped = strip.strip_pdf(original)

    reader = PdfReader(io.BytesIO(stripped))
    assert not reader.metadata


def test_strip_pdf_clears_xmp() -> None:
    original = binaries.pdf_with_xmp_creator("Person Name")
    stripped = strip.strip_pdf(original)

    reader = PdfReader(io.BytesIO(stripped))
    assert reader.xmp_metadata is None


def test_pdf_droppable_reports_info_and_xmp() -> None:
    original = binaries.pdf_with_author("Person Name")
    assert strip.describe(original) == ["PDF Info dictionary"]
    assert strip.describe(strip.strip_pdf(original)) == []


# -- OOXML --------------------------------------------------------------------------


def _field_names(content: bytes, rule_id: str) -> set[str]:
    return {f.name for f in extract_fields("ooxml", content) if f.rule_id == rule_id}


def test_strip_ooxml_blanks_creator_keeps_comments_and_tracked_changes() -> None:
    original = binaries.minimal_docx(
        creator="Person Name",
        tracked_change_author="Person Name",
        comment_author="Person Name",
    )
    stripped = strip.strip_ooxml(original)

    assert "creator" not in _field_names(stripped, "ooxml-core")
    assert _field_names(stripped, "ooxml-revision-author") == {"author"}
    assert _field_names(stripped, "ooxml-comment-author") == {"author"}


def test_strip_ooxml_blanks_company() -> None:
    original = binaries.minimal_xlsx(company="Acme Corp")
    stripped = strip.strip_ooxml(original)

    assert "Company" not in _field_names(stripped, "ooxml-app")


def test_ooxml_droppable_lists_core_and_app_fields_not_comments() -> None:
    original = binaries.minimal_docx(creator="Person Name", comment_author="Person Name")

    described = strip.describe(original)

    assert described == ["docProps/core.xml creator"]
    assert strip.describe(strip.strip_ooxml(original)) == []


# -- dispatch -----------------------------------------------------------------------


def test_strip_bytes_leaves_text_content_unchanged() -> None:
    text = b"hello world\n"
    assert strip.strip_bytes(text) == text
    assert strip.describe(text) == []


def test_strip_bytes_dispatches_by_magic_bytes() -> None:
    original = binaries.jpeg_with_field(ExifTag.Artist.value, "Person Name")
    assert strip.strip_bytes(original) == strip.strip_jpeg(original)
