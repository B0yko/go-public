"""Binary content generators for benchmark plants:
images with EXIF/GPS, a PNG with text chunks, a WebP with EXIF, PDFs, minimal
hand-written OOXML packages.

No dev-only dependency: `Pillow`/`pypdf` are runtime deps (already used by
`detect/binary_meta.py`), and the OOXML packages are built by hand with `zipfile` +
string templates rather than `python-docx`/`openpyxl` (those stay dev-only, used only
by the packaging test that confirms these hand-written bytes are valid packages).

Fictional coordinates/names/organisations only, assembled from parts
(`bench/plants/_fictional.py`).
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib

from PIL import Image
from PIL.ExifTags import Base as ExifTag
from PIL.TiffImagePlugin import IFDRational
from pypdf import PdfWriter

# -- EXIF-bearing images (JPEG/TIFF/WebP) -------------------------------------------


def _degrees_to_dms(value: float) -> tuple[IFDRational, IFDRational, IFDRational]:
    value = abs(value)
    degrees = int(value)
    minutes_full = (value - degrees) * 60
    minutes = int(minutes_full)
    seconds = round((minutes_full - minutes) * 60, 2)
    return (IFDRational(degrees, 1), IFDRational(minutes, 1), IFDRational(int(seconds * 100), 100))


def _gps_ifd(lat: float, lon: float) -> dict[int, object]:
    return {
        1: "N" if lat >= 0 else "S",
        2: _degrees_to_dms(lat),
        3: "E" if lon >= 0 else "W",
        4: _degrees_to_dms(lon),
    }


def jpeg_with_gps(lat: float, lon: float) -> bytes:
    """A tiny JPEG whose EXIF GPS IFD holds `(lat, lon)` (fictional coordinates)."""
    exif = Image.Exif()
    exif[ExifTag.GPSInfo.value] = _gps_ifd(lat, lon)
    return _save_jpeg(exif)


def jpeg_with_field(tag: int, value: str) -> bytes:
    """A tiny JPEG carrying one text EXIF tag (Artist, Copyright, Software, ...)."""
    exif = Image.Exif()
    exif[tag] = value
    return _save_jpeg(exif)


def _save_jpeg(exif: Image.Exif) -> bytes:
    img = Image.new("RGB", (4, 4), color=(120, 40, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    return buf.getvalue()


def webp_with_field(tag: int, value: str) -> bytes:
    """A tiny WebP carrying one text EXIF tag."""
    exif = Image.Exif()
    exif[tag] = value
    img = Image.new("RGB", (4, 4), color=(10, 20, 30))
    buf = io.BytesIO()
    img.save(buf, format="WEBP", exif=exif.tobytes())
    return buf.getvalue()


def tiff_with_field(tag: int, value: str) -> bytes:
    """A tiny TIFF carrying one text EXIF tag."""
    exif = Image.Exif()
    exif[tag] = value
    img = Image.new("RGB", (4, 4), color=(50, 60, 70))
    buf = io.BytesIO()
    img.save(buf, format="TIFF", exif=exif.tobytes())
    return buf.getvalue()


# -- PNG (chunks spliced in directly, since Pillow exposes no public tIME/eXIf
# writer; `detect/binary_meta.py` parses chunks directly too, so this is the same
# format both sides agree on) ------------------------------------------------------


def _png_chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data))


def _insert_after_ihdr(png: bytes, chunk: bytes) -> bytes:
    (length,) = struct.unpack(">I", png[8:12])
    ihdr_end = 8 + 8 + length + 4
    return png[:ihdr_end] + chunk + png[ihdr_end:]


def _blank_png() -> bytes:
    img = Image.new("RGB", (4, 4), color=(5, 5, 5))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def png_with_text(keyword: str, value: str) -> bytes:
    """A tiny PNG with one `tEXt` chunk."""
    data = keyword.encode("latin-1") + b"\x00" + value.encode("latin-1")
    return _insert_after_ihdr(_blank_png(), _png_chunk(b"tEXt", data))


def png_with_time(year: int, month: int, day: int, hour: int, minute: int, second: int) -> bytes:
    """A tiny PNG with one `tIME` chunk."""
    data = struct.pack(">HBBBBB", year, month, day, hour, minute, second)
    return _insert_after_ihdr(_blank_png(), _png_chunk(b"tIME", data))


def png_with_exif(tag: int, value: str) -> bytes:
    """A tiny PNG with an `eXIf` chunk (raw EXIF/TIFF bytes, same as embedded in a
    real photo's PNG export)."""
    exif = Image.Exif()
    exif[tag] = value
    return _insert_after_ihdr(_blank_png(), _png_chunk(b"eXIf", exif.tobytes()))


# -- PDF (pypdf) ---------------------------------------------------------------------


def pdf_without_metadata() -> bytes:
    """A minimal PDF with no Info dictionary at all: `pypdf.PdfWriter` sets its own
    `/Producer` by default, so this clears it explicitly (filler PDFs carry no
    Producer/Info)."""
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.metadata = {}
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def pdf_with_author(name: str) -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.metadata = {"/Author": name}
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def pdf_with_xmp_creator(name: str) -> bytes:
    xmp = (
        '<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f"<dc:creator><rdf:Seq><rdf:li>{name}</rdf:li></rdf:Seq></dc:creator>"
        '</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
    ).encode()
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.metadata = {}
    writer.xmp_metadata = xmp
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


#: `zipfile.ZipFile.writestr(name, data)` (the bare-string form) stamps every entry
#: with `time.localtime()` when no `ZipInfo` is given, which would make the OOXML
#: bytes below — and so every fixture build — non-deterministic (two runs on one machine
#: must give identical `git rev-parse --all`). A fixed `ZipInfo`
#: date avoids that.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def _zip_write(zf: zipfile.ZipFile, name: str, content: str) -> None:
    info = zipfile.ZipInfo(name, date_time=_ZIP_EPOCH)
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, content)


# -- OOXML (hand-written zip; no python-docx/openpyxl at build time) ---------------

_CONTENT_TYPES_DOCX_BASE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
<Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>
{comments_override}</Types>"""
_COMMENTS_CONTENT_TYPE = (
    '<Override PartName="/word/comments.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>\n'
)

_RELS_DOCX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>
</Relationships>"""

_DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>
</Relationships>"""

_APP_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
<Company>{company}</Company>
</Properties>"""

_CORE_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:creator>{creator}</dc:creator>
</cp:coreProperties>"""

_CUSTOM_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>"""


def _document_xml(*, tracked_change_author: str | None) -> str:
    body = "<w:p><w:r><w:t>Hello.</w:t></w:r></w:p>"
    if tracked_change_author is not None:
        body += (
            f'<w:p><w:ins w:id="1" w:author="{tracked_change_author}" '
            'w:date="2024-01-01T00:00:00Z"><w:r><w:t>Inserted.</w:t></w:r></w:ins></w:p>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}<w:sectPr/></w:body></w:document>"
    )


def _comments_xml(author: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:comment w:id="0" w:author="{author}" w:date="2024-01-01T00:00:00Z">'
        "<w:p><w:r><w:t>A comment.</w:t></w:r></w:p></w:comment></w:comments>"
    )


def minimal_docx(
    *,
    creator: str = "",
    tracked_change_author: str | None = None,
    comment_author: str | None = None,
) -> bytes:
    """A minimal, valid `.docx` package (loads in `python-docx`; dev-only test).

    `word/comments.xml` (and its content-type/relationship entries) is included only
    when `comment_author` is given, so a plant that only wants a `creator`/tracked-
    change finding never picks up an unplanned `ooxml-comment-author` finding too.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        comments_override = _COMMENTS_CONTENT_TYPE if comment_author is not None else ""
        _zip_write(
            zf,
            "[Content_Types].xml",
            _CONTENT_TYPES_DOCX_BASE.format(comments_override=comments_override),
        )
        _zip_write(zf, "_rels/.rels", _RELS_DOCX)
        _zip_write(
            zf, "word/document.xml", _document_xml(tracked_change_author=tracked_change_author)
        )
        _zip_write(zf, "docProps/core.xml", _CORE_XML.format(creator=creator))
        _zip_write(zf, "docProps/app.xml", _APP_XML.format(company=""))
        _zip_write(zf, "docProps/custom.xml", _CUSTOM_XML)
        if comment_author is not None:
            _zip_write(zf, "word/_rels/document.xml.rels", _DOC_RELS)
            _zip_write(zf, "word/comments.xml", _comments_xml(comment_author))
    return buf.getvalue()


_CONTENT_TYPES_XLSX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_RELS_XLSX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""

_WORKBOOK_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>
</workbook>"""

_WORKBOOK_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"""

_SHEET_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>hello</t></is></c></row></sheetData>
</worksheet>"""


def minimal_xlsx(*, company: str = "") -> bytes:
    """A minimal, valid `.xlsx` package (loads in `openpyxl`; dev-only test)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        _zip_write(zf, "[Content_Types].xml", _CONTENT_TYPES_XLSX)
        _zip_write(zf, "_rels/.rels", _RELS_XLSX)
        _zip_write(zf, "xl/workbook.xml", _WORKBOOK_XML)
        _zip_write(zf, "xl/_rels/workbook.xml.rels", _WORKBOOK_RELS)
        _zip_write(zf, "xl/worksheets/sheet1.xml", _SHEET_XML)
        _zip_write(zf, "docProps/core.xml", _CORE_XML.format(creator=""))
        _zip_write(zf, "docProps/app.xml", _APP_XML.format(company=company))
    return buf.getvalue()
