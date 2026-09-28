"""`detect/base.py` routing: magic bytes, NUL/UTF-16 check, `max_scan_mb` gate.

Stage 2b brief: "a PDF with no NUL in its first 8 KB reaches the PDF extractor" and
architecture.md's routing rules. No real image/PDF/OOXML bytes are needed to test
*routing* (only the magic bytes / zip manifest matter); real extraction is stage 3b.
"""

from __future__ import annotations

import io
import zipfile

from go_public.detect.base import BINARY_KINDS, extract_binary_fields, route_blob


def test_jpeg_magic_bytes_route_to_jpeg() -> None:
    content = b"\xff\xd8\xff\xe0" + b"\x00" * 100  # NULs would misroute as binary
    assert route_blob(content).kind == "jpeg"


def test_png_magic_bytes_route_to_png() -> None:
    content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    assert route_blob(content).kind == "png"


def test_tiff_little_and_big_endian_route_to_tiff() -> None:
    assert route_blob(b"II*\x00" + b"\x01" * 20).kind == "tiff"
    assert route_blob(b"MM\x00*" + b"\x01" * 20).kind == "tiff"


def test_webp_riff_container_routes_to_webp() -> None:
    content = b"RIFF" + (100).to_bytes(4, "little") + b"WEBPVP8 " + b"\x00" * 50
    assert route_blob(content).kind == "webp"


def test_pdf_signature_within_first_1024_bytes_routes_to_pdf() -> None:
    # A leading comment before the header, as some real PDF producers emit; no NUL
    # anywhere in the content, so this must not fall through to the NUL-binary check.
    content = b"%leading-junk\n" + b"%PDF-1.4\n" + b"1 0 obj\n<< >>\nendobj\n"
    assert b"\x00" not in content[:8000]
    result = route_blob(content)
    assert result.kind == "pdf"
    assert "pdf" in BINARY_KINDS


def test_pdf_signature_must_be_within_the_first_1024_bytes() -> None:
    padding = b"x" * 1100
    content = padding + b"%PDF-1.4\n"
    assert route_blob(content).kind != "pdf"


def test_zip_with_ooxml_manifest_and_word_part_routes_to_ooxml() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
    assert route_blob(buf.getvalue()).kind == "ooxml"


def test_zip_without_ooxml_manifest_routes_to_archive() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("readme.txt", "just a plain zip")
    assert route_blob(buf.getvalue()).kind == "archive"


def test_nul_in_first_8000_bytes_routes_to_binary() -> None:
    content = b"hello\x00world" + b"x" * 100
    assert route_blob(content).kind == "binary"


def test_nul_after_8000_bytes_does_not_force_binary() -> None:
    content = b"a" * 8000 + b"\x00more text after the scan window"
    assert route_blob(content).kind == "text"


def test_utf16_le_bom_decodes_as_text_despite_internal_nuls() -> None:
    content = "hello world".encode("utf-16-le")
    content = b"\xff\xfe" + content
    result = route_blob(content)
    assert result.kind == "text"
    assert result.text == "hello world"


def test_utf16_be_bom_decodes_as_text() -> None:
    content = b"\xfe\xff" + "secret token".encode("utf-16-be")
    result = route_blob(content)
    assert result.kind == "text"
    assert result.text == "secret token"


def test_plain_ascii_text_routes_to_text() -> None:
    result = route_blob(b"just some ordinary source code\n")
    assert result.kind == "text"
    assert result.text == "just some ordinary source code\n"


def test_oversized_text_blob_routes_to_large_instead_of_text() -> None:
    content = b"a" * (2 * 1024 * 1024)
    result = route_blob(content, max_scan_mb=1)
    assert result.kind == "large"
    assert result.text is None


def test_extract_binary_fields_is_empty_for_unparseable_content_of_every_binary_kind() -> None:
    """`extract_binary_fields` delegates to `detect/binary_meta.py` (stage 3b); real
    extraction from valid content is that module's own tests. Here: garbage bytes
    never crash routing and never fabricate a field."""
    for kind in BINARY_KINDS:
        assert extract_binary_fields(kind, b"anything") == []
