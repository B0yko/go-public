"""`detect/binary_meta.py`: real extraction from every generator `bench/binaries.py`
provides, plus the defensive "malformed content never crashes" contract.
"""

from __future__ import annotations

import logging

import pytest
from PIL.ExifTags import Base as ExifTag

from go_public.bench import binaries
from go_public.detect import binary_meta


def _field(fields: list[binary_meta.BinaryField], name: str) -> binary_meta.BinaryField:
    matches = [f for f in fields if f.name == name]
    assert len(matches) == 1, f"expected exactly one {name!r} field, got {fields}"
    return matches[0]


def test_jpeg_gps_is_extracted_as_exif_gps_high() -> None:
    content = binaries.jpeg_with_gps(24.716, -60.583)
    fields = binary_meta.extract_fields("jpeg", content)
    gps = _field(fields, "GPSInfo")
    assert gps.rule_id == "exif-gps"
    assert gps.severity == "high"
    lat, lon = (float(x) for x in gps.value.split(","))
    assert abs(lat - 24.716) < 0.01
    assert abs(lon - (-60.583)) < 0.01


def test_jpeg_artist_is_exif_person_medium() -> None:
    content = binaries.jpeg_with_field(ExifTag.Artist.value, "Jordan Rivera")
    fields = binary_meta.extract_fields("jpeg", content)
    artist = _field(fields, "Artist")
    assert (artist.rule_id, artist.severity, artist.value) == (
        "exif-person",
        "medium",
        "Jordan Rivera",
    )


def test_jpeg_software_is_exif_software_low() -> None:
    content = binaries.jpeg_with_field(ExifTag.Software.value, "AcmeEditor 1.0")
    fields = binary_meta.extract_fields("jpeg", content)
    software = _field(fields, "Software")
    assert (software.rule_id, software.severity) == ("exif-software", "low")


def test_webp_copyright_is_exif_org_medium() -> None:
    content = binaries.webp_with_field(ExifTag.Copyright.value, "Northwind Imaging Co")
    fields = binary_meta.extract_fields("webp", content)
    copyright_field = _field(fields, "Copyright")
    assert (copyright_field.rule_id, copyright_field.severity) == ("exif-org", "medium")


def test_tiff_artist_is_extracted() -> None:
    content = binaries.tiff_with_field(ExifTag.Artist.value, "Jordan Rivera")
    fields = binary_meta.extract_fields("tiff", content)
    assert _field(fields, "Artist").rule_id == "exif-person"


def test_png_text_author_keyword_is_medium() -> None:
    content = binaries.png_with_text("Author", "Jordan Rivera")
    fields = binary_meta.extract_fields("png", content)
    author = _field(fields, "Author")
    assert (author.rule_id, author.severity, author.value) == (
        "png-text",
        "medium",
        "Jordan Rivera",
    )


def test_png_text_non_person_keyword_is_low() -> None:
    content = binaries.png_with_text("Comment", "just a comment")
    fields = binary_meta.extract_fields("png", content)
    comment = _field(fields, "Comment")
    assert (comment.rule_id, comment.severity) == ("png-text", "low")


def test_png_time_chunk_is_extracted() -> None:
    content = binaries.png_with_time(2024, 1, 2, 3, 4, 5)
    fields = binary_meta.extract_fields("png", content)
    time_field = _field(fields, "Time")
    assert time_field.rule_id == "png-time"
    assert time_field.value == "2024-01-02 03:04:05"


def test_png_embedded_exif_uses_png_exif_rule_except_gps() -> None:
    content = binaries.png_with_exif(ExifTag.Artist.value, "Jordan Rivera")
    fields = binary_meta.extract_fields("png", content)
    assert _field(fields, "Artist").rule_id == "png-exif"


def test_pdf_author_is_pdf_info_medium() -> None:
    content = binaries.pdf_with_author("Jordan Rivera")
    fields = binary_meta.extract_fields("pdf", content)
    author = _field(fields, "Author")
    assert (author.rule_id, author.severity, author.value) == (
        "pdf-info",
        "medium",
        "Jordan Rivera",
    )


def test_pdf_without_metadata_yields_no_fields() -> None:
    content = binaries.pdf_without_metadata()
    assert binary_meta.extract_fields("pdf", content) == []


def test_pdf_xmp_creator_is_pdf_xmp_medium() -> None:
    content = binaries.pdf_with_xmp_creator("Morgan Ellis")
    fields = binary_meta.extract_fields("pdf", content)
    creator = _field(fields, "dc:creator")
    assert (creator.rule_id, creator.severity, creator.value) == (
        "pdf-xmp",
        "medium",
        "Morgan Ellis",
    )


def test_docx_creator_is_ooxml_core_medium() -> None:
    content = binaries.minimal_docx(creator="Casey Morgan")
    fields = binary_meta.extract_fields("ooxml", content)
    creator = _field(fields, "creator")
    assert (creator.rule_id, creator.severity, creator.value) == (
        "ooxml-core",
        "medium",
        "Casey Morgan",
    )


def test_docx_with_no_creator_yields_no_core_field() -> None:
    content = binaries.minimal_docx()
    assert binary_meta.extract_fields("ooxml", content) == []


def test_docx_tracked_change_author_is_ooxml_revision_author() -> None:
    content = binaries.minimal_docx(tracked_change_author="Robin Taylor")
    fields = binary_meta.extract_fields("ooxml", content)
    author = _field(fields, "author")
    assert (author.rule_id, author.value) == ("ooxml-revision-author", "Robin Taylor")


def test_docx_comment_author_is_ooxml_comment_author() -> None:
    content = binaries.minimal_docx(comment_author="Avery Quinn")
    fields = binary_meta.extract_fields("ooxml", content)
    author = _field(fields, "author")
    assert (author.rule_id, author.value) == ("ooxml-comment-author", "Avery Quinn")


def test_xlsx_company_is_ooxml_app_medium() -> None:
    content = binaries.minimal_xlsx(company="Silverline Fictional Ltd")
    fields = binary_meta.extract_fields("ooxml", content)
    company = _field(fields, "Company")
    assert (company.rule_id, company.severity, company.value) == (
        "ooxml-app",
        "medium",
        "Silverline Fictional Ltd",
    )


def test_xlsx_with_no_company_yields_no_app_field() -> None:
    content = binaries.minimal_xlsx()
    assert binary_meta.extract_fields("ooxml", content) == []


def test_garbage_bytes_never_crash_any_extractor() -> None:
    for kind in ("jpeg", "tiff", "webp", "png", "pdf", "ooxml"):
        assert binary_meta.extract_fields(kind, b"not a real file") == []


def test_unknown_kind_yields_no_fields() -> None:
    assert binary_meta.extract_fields("archive", b"PK\x03\x04") == []


def test_text_mentioning_pdf_header_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    text = b'"""The reader looks for %PDF- near the start."""\n' * 3
    with caplog.at_level(logging.DEBUG):
        assert binary_meta.extract_fields("pdf", text) == []
    assert [r for r in caplog.records if r.name.startswith("pypdf")] == []
