"""`redaction.py`: secret masking for report previews (product spec item 11)."""

from __future__ import annotations

from go_public.detect.base import Detection
from go_public.model import sha256_hex
from go_public.redaction import make_preview, mask_secret_spans, redact_secret


def test_redact_secret_shows_first_four_chars_length_and_hash_prefix() -> None:
    value = "AKIA" + "ABCDEFGHIJKLMNOP"
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


def _detection(text: str, start: int, end: int) -> Detection:
    return Detection(
        category="secret",
        rule_id="r",
        severity="critical",
        start=start,
        end=end,
        line=1,
        col=start + 1,
        value=text[start:end],
        secret=True,
    )


def test_mask_secret_spans_never_leaves_the_tail_of_an_overlapping_span() -> None:
    text = "key = " + "AKIA" + "1234567890ABCDEF" + "zzzzzz_tail_of_a_longer_match" + " end"
    first = _detection(text, 6, 26)
    longer = _detection(text, 12, len(text) - 4)

    masked = mask_secret_spans(text, [first, longer])

    assert "zzzzzz" not in masked
    assert "tail_of_a_longer_match" not in masked
    assert masked.startswith("key = ")
    assert masked.endswith(" end")


def test_mask_secret_spans_handles_a_nested_span_and_multibyte_text() -> None:
    text = "héllo → " + "tok_ABCDEFGHIJKLMNOPQRST" + " ✓"
    outer = _detection(text, 8, 8 + 24)
    inner = _detection(text, 12, 20)

    masked = mask_secret_spans(text, [inner, outer])

    assert "ABCDEFGH" not in masked
    assert masked.startswith("héllo → ")
    assert masked.endswith(" ✓")
