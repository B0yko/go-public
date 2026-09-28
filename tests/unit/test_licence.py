"""`detect/licence.py`: key-phrase identification, SPDX headers, copyright holder
extraction, and the proprietary/confidential notice detector.
"""

from __future__ import annotations

from go_public.detect import licence


def test_mit_text_is_identified() -> None:
    text = "Permission is hereby granted, free of charge, to any person obtaining a copy"
    assert licence.identify_licence_text(text) == "MIT"


def test_apache_2_0_text_is_identified() -> None:
    text = "Apache License\nVersion 2.0, January 2004\n"
    assert licence.identify_licence_text(text) == "Apache-2.0"


def test_bsd_3_clause_needs_both_phrases() -> None:
    text = (
        "Redistribution and use in source and binary forms, with or without\n"
        "modification... Neither the name of the copyright holder...\n"
    )
    assert licence.identify_licence_text(text) == "BSD-3-Clause"


def test_bsd_2_clause_is_identified_without_neither_the_name() -> None:
    text = "Redistribution and use in source and binary forms, with or without modification"
    assert licence.identify_licence_text(text) == "BSD-2-Clause"


def test_unlicense_needs_both_phrases() -> None:
    text = "This is free and unencumbered software released into the public domain."
    assert licence.identify_licence_text(text) == "Unlicense"


def test_gpl_and_lgpl_are_distinguished_by_version() -> None:
    assert licence.identify_licence_text("GNU General Public License\nVersion 3") == "GPL-3.0"
    assert licence.identify_licence_text("GNU General Public License\nVersion 2") == "GPL-2.0"
    assert (
        licence.identify_licence_text("GNU Lesser General Public License\nVersion 3") == "LGPL-3.0"
    )


def test_proprietary_via_keyword() -> None:
    assert licence.identify_licence_text("This module is Confidential.") == "proprietary"


def test_proprietary_via_all_rights_reserved_without_grant() -> None:
    text = "Copyright 2024 Someone. All rights reserved."
    assert licence.identify_licence_text(text) == "proprietary"


def test_all_rights_reserved_with_grant_is_not_proprietary() -> None:
    text = "All rights reserved except as permission is hereby granted under this licence."
    assert licence.identify_licence_text(text) == "unknown"


def test_unrecognised_text_is_unknown() -> None:
    assert licence.identify_licence_text("Just some ordinary prose.") == "unknown"


def test_spdx_header_maps_to_canonical_label() -> None:
    text = "# SPDX-License-Identifier: Apache-2.0\n"
    assert licence.identify_spdx_header(text) == "Apache-2.0"


def test_spdx_header_with_or_later_suffix_maps_to_base_label() -> None:
    text = "SPDX-License-Identifier: GPL-3.0-or-later\n"
    assert licence.identify_spdx_header(text) == "GPL-3.0"


def test_spdx_header_unrecognised_id_is_unknown() -> None:
    text = "SPDX-License-Identifier: SomeMadeUpLicence-1.0\n"
    assert licence.identify_spdx_header(text) == "unknown"


def test_no_spdx_header_returns_none() -> None:
    assert licence.identify_spdx_header("no header here") is None


def test_is_licence_file_path_matches_common_prefixes() -> None:
    assert licence.is_licence_file_path("LICENSE")
    assert licence.is_licence_file_path("LICENSE.md")
    assert licence.is_licence_file_path("LICENCE.txt")
    assert licence.is_licence_file_path("COPYING")
    assert licence.is_licence_file_path("docs/LICENSE")
    assert not licence.is_licence_file_path("license.py")


def test_is_manifest_path_matches_only_known_basenames() -> None:
    assert licence.is_manifest_path("pyproject.toml")
    assert licence.is_manifest_path("frontend/package.json")
    assert licence.is_manifest_path("Cargo.toml")
    assert not licence.is_manifest_path("other.toml")


def test_identify_path_content_reads_pyproject_license_field() -> None:
    content = b'[project]\nname = "x"\nlicense = "MIT"\n'
    assert licence.identify_path_content("pyproject.toml", content) == "MIT"


def test_identify_path_content_reads_package_json_license_field() -> None:
    content = b'{"license": "Apache-2.0"}'
    assert licence.identify_path_content("package.json", content) == "Apache-2.0"


def test_identify_path_content_reads_cargo_toml_license_field() -> None:
    content = b'[package]\nname = "x"\nlicense = "MIT"\n'
    assert licence.identify_path_content("Cargo.toml", content) == "MIT"


def test_manifest_with_no_license_field_returns_none() -> None:
    content = b'[project]\nname = "x"\n'
    assert licence.identify_path_content("pyproject.toml", content) is None


def test_malformed_manifest_never_raises() -> None:
    assert licence.identify_path_content("pyproject.toml", b"not { valid toml [") is None
    assert licence.identify_path_content("package.json", b"not json") is None


def test_unrelated_path_returns_none() -> None:
    assert licence.identify_path_content("src/main.py", b"print(1)") is None


def test_extract_copyright_holder() -> None:
    text = "Copyright (c) 2024 Riverside Fictional Holdings\n\nOther text.\n"
    assert licence.extract_copyright_holder(text) == "Riverside Fictional Holdings"


def test_extract_copyright_holder_with_year_range_and_symbol() -> None:
    text = "Copyright © 2020-2024, Pat Public\n"
    assert licence.extract_copyright_holder(text) == "Pat Public"


def test_extract_copyright_holder_returns_none_when_absent() -> None:
    assert licence.extract_copyright_holder("no notice here") is None


def test_detect_notice_fires_on_leading_comment_marker() -> None:
    detection = licence.detect_notice("// Confidential: internal draft.\n")
    assert detection is not None
    assert detection.category == "licence"
    assert detection.rule_id == "licence-proprietary"
    assert detection.severity == "high"
    assert detection.line == 1


def test_detect_notice_requires_word_at_line_start() -> None:
    assert licence.detect_notice("This code is not confidential at all.") is None


def test_detect_notice_ignores_prose_discussing_the_concept() -> None:
    text = "The Data section explains proprietary licences in the abstract.\n"
    assert licence.detect_notice(text) is None


def test_detect_notice_on_a_later_comment_line_reports_that_line() -> None:
    text = "line one\nline two\n// Proprietary and confidential.\n"
    detection = licence.detect_notice(text)
    assert detection is not None
    assert detection.line == 3


def test_detect_notice_ignores_a_markdown_body_line_with_no_comment_marker() -> None:
    """stage-4.md's notice-detector fix: a plain-prose line that opens with the word
    (no comment marker, not a licence-relevant path) is not a notice."""
    text = "Some heading\n\nProprietary and confidential.\nMore text.\n"
    assert licence.detect_notice(text) is None


def test_detect_notice_ignores_lines_past_the_header_block() -> None:
    text = "\n".join([f"line {i}" for i in range(1, 31)] + ["// Confidential notice"])
    assert licence.detect_notice(text) is None


def test_detect_notice_reads_a_licence_relevant_file_anywhere_with_no_marker() -> None:
    text = "\n".join([f"line {i}" for i in range(1, 40)] + ["Confidential and internal."])
    detection = licence.detect_notice(text, licence_relevant=True)
    assert detection is not None
    assert detection.line == 40


def test_detect_notice_all_rights_reserved_without_grant_in_licence_file() -> None:
    text = "Copyright 2024 Someone.\n\nAll rights reserved. No further rights granted.\n"
    detection = licence.detect_notice(text, licence_relevant=True)
    assert detection is not None
    assert detection.line == 3
    assert detection.value.startswith("All rights reserved")


def test_detect_notice_all_rights_reserved_with_grant_is_not_flagged() -> None:
    text = "Copyright 2024 Someone.\n\nAll rights reserved except as licensed under this file.\n"
    assert licence.detect_notice(text, licence_relevant=True) is None


def test_detect_notice_all_rights_reserved_needs_a_comment_marker_elsewhere() -> None:
    text = "All rights reserved by the author, informally speaking.\n"
    assert licence.detect_notice(text) is None
