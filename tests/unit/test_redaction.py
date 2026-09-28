"""`redaction.py`: secret masking for report previews (product spec item 11)."""

from __future__ import annotations

from go_public.model import sha256_hex
from go_public.redaction import make_preview, redact_secret


def test_redact_secret_shows_first_four_chars_length_and_hash_prefix() -> None:
    value = "***REMOVED***"
    result = redact_secret(value)
    assert result.startswith("AKIA…")
    assert f"[len={len(value)} " in result
    assert sha256_hex(value)[:8] in result
    assert value[4:] not in result


def test_redact_secret_never_leaks_the_full_value() -> None:
    value = "supersecrettoken1234567890"
    assert value not in redact_secret(value)


def test_make_preview_masks_secrets_by_default() -> None:
    value = "supersecrettoken1234567890"
    preview = make_preview(value, secret=True, show_secrets=False)
    assert value not in preview
    assert preview == redact_secret(value)


def test_make_preview_shows_full_value_with_show_secrets() -> None:
    value = "supersecrettoken1234567890"
    assert make_preview(value, secret=True, show_secrets=True) == value


def test_make_preview_never_masks_non_secret_findings() -> None:
    value = "some-non-secret-context"
    assert make_preview(value, secret=False, show_secrets=False) == value
