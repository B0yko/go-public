"""Binary-metadata plants (product spec item 6; stage-3.md 3b), one per
`detect/binary_meta.py` rule id the Data section's small-seed table names — plus two
extra fields (`pdf-xmp`, `ooxml-comment-author`) so all ten small-seed plants land on
a distinct, independently verifiable field rather than repeating a rule id.

Every plant places its generated file via `binary_field` (fixture-api.md), with
`field_name` set to exactly the name `detect/binary_meta.py`'s own extractor gives
that field, so `bench/match.py`'s `(blob, field)` key lines up without guessing.
"""

from __future__ import annotations

import random

from PIL.ExifTags import Base as ExifTag

from go_public.bench import binaries
from go_public.bench.plants import FixtureContext, Plant
from go_public.bench.plants._fictional import (
    EXIF_ORG_NAME,
    EXIF_PERSON_NAME,
    OOXML_COMMENT_AUTHOR,
    OOXML_COMPANY_NAME,
    OOXML_CREATOR_NAME,
    OOXML_REVISION_AUTHOR,
    PDF_XMP_CREATOR_NAME,
)

_COUNTS: dict[str, int] = {"tiny": 4, "small": 10}

#: A fictional GPS fix (Data section: "coordinates... fictional"): open ocean,
#: nowhere near a real address.
_GPS_LAT = 24.716
_GPS_LON = -60.583


def _templates() -> list[tuple[str, str, str, bytes]]:
    """`(path, rule_id, field, content)` for all ten binary-metadata plants, in a
    fixed order so `tiny` (a prefix of this list) still covers a wide mix of rule ids
    and container formats."""
    return [
        (
            "markers/binary-metadata-00.jpg",
            "exif-gps",
            "GPSInfo",
            binaries.jpeg_with_gps(_GPS_LAT, _GPS_LON),
        ),
        (
            "markers/binary-metadata-01.jpg",
            "exif-person",
            "Artist",
            binaries.jpeg_with_field(ExifTag.Artist.value, EXIF_PERSON_NAME),
        ),
        (
            "markers/binary-metadata-02.docx",
            "ooxml-core",
            "creator",
            binaries.minimal_docx(creator=OOXML_CREATOR_NAME),
        ),
        (
            "markers/binary-metadata-03.xlsx",
            "ooxml-app",
            "Company",
            binaries.minimal_xlsx(company=OOXML_COMPANY_NAME),
        ),
        (
            "markers/binary-metadata-04.png",
            "png-text",
            "Author",
            binaries.png_with_text("Author", EXIF_PERSON_NAME),
        ),
        (
            "markers/binary-metadata-05.webp",
            "exif-org",
            "Copyright",
            binaries.webp_with_field(ExifTag.Copyright.value, EXIF_ORG_NAME),
        ),
        (
            "markers/binary-metadata-06.pdf",
            "pdf-info",
            "Author",
            binaries.pdf_with_author(EXIF_PERSON_NAME),
        ),
        (
            "markers/binary-metadata-07.docx",
            "ooxml-revision-author",
            "author",
            binaries.minimal_docx(tracked_change_author=OOXML_REVISION_AUTHOR),
        ),
        (
            "markers/binary-metadata-08.docx",
            "ooxml-comment-author",
            "author",
            binaries.minimal_docx(comment_author=OOXML_COMMENT_AUTHOR),
        ),
        (
            "markers/binary-metadata-09.pdf",
            "pdf-xmp",
            "dc:creator",
            binaries.pdf_with_xmp_creator(PDF_XMP_CREATOR_NAME),
        ),
    ]


def generate(rng: random.Random, ctx: FixtureContext, *, size: str) -> list[Plant]:
    """Build every binary-metadata plant for `size`. `rng`/`ctx` accepted for
    signature parity (fixture-api.md); every plant's content is a fixed fictional
    value, so neither is needed here."""
    del rng, ctx
    total = _COUNTS[size]
    return [
        Plant(
            plant_id=f"binary-metadata-{index:02d}",
            category="binary-metadata",
            location_type="binary_field",
            path=path,
            content=content,
            field_name=field,
            eval_class="binary-metadata",
            rule_family=rule_id,
        )
        for index, (path, rule_id, field, content) in enumerate(_templates()[:total])
    ]
