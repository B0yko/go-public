"""`detect/pii.py`: emails, phone numbers and flagged names."""

from __future__ import annotations

from go_public.detect.pii import PiiDetector


def _rule_ids(text: str, **kwargs: object) -> list[str]:
    detector = PiiDetector(**kwargs)  # type: ignore[arg-type]
    return [d.rule_id for d in detector.detect(text)]


def test_email_is_detected() -> None:
    hits = _rule_ids("contact me at ***REMOVED*** please")
    assert hits == ["pii-email"]


def test_reserved_domain_email_is_not_flagged() -> None:
    assert _rule_ids("contact me at pat@example.com") == []
    assert _rule_ids("contact me at pat@sub.example.test") == []


def test_allowlisted_identity_email_is_not_flagged() -> None:
    detector = PiiDetector(identity_allow=("Pat Public <pat@example.org>",))
    assert detector.detect("pat@example.org is fine") == []


def test_nanp_555_range_phone_is_detected() -> None:
    hits = _rule_ids("call ***REMOVED*** today", phone_regions=("US",))
    assert hits == ["pii-phone"]


def test_gb_ofcom_drama_range_phone_is_detected() -> None:
    hits = _rule_ids("call ***REMOVED*** today", phone_regions=("GB",))
    assert hits == ["pii-phone"]


def test_international_format_phone_is_always_detected() -> None:
    hits = _rule_ids("call ***REMOVED*** today", phone_regions=("US",))
    assert hits == ["pii-phone"]


def test_configured_name_is_detected_whole_word_case_insensitive() -> None:
    detector = PiiDetector(names=frozenset({"Alex Rivera"}))
    hits = [d.value for d in detector.detect("met with alex rivera yesterday")]
    assert hits == ["alex rivera"]
    assert detector.detect("alexrivera99 is a handle") == []


def test_text_with_no_digits_finds_no_phone() -> None:
    assert _rule_ids("no digits here at all", phone_regions=("US", "GB", "DE")) == []


def test_order_number_digit_run_is_not_a_phone() -> None:
    # A hard negative from the Data section: an order-number-shaped run of digits
    # must not be mistaken for a phone number.
    assert _rule_ids("order number 48213097", phone_regions=("US", "GB", "DE")) == []
