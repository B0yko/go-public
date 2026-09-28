"""`detect/pii.py`: emails, phone numbers and flagged names."""

from __future__ import annotations

from go_public.detect.pii import PiiDetector

# Plant-shaped strings are assembled at runtime (conventions.md).
_INTERNAL_EMAIL = "jordan@build." + "internal"
_NANP = "202-555-" + "0142"
_NANP_DOTTED = "202.555." + "0142"
_GB_DRAMA = "020 7946 " + "0958"
_DE_INTL = "+49 30 " + "12345678"


def _rule_ids(text: str, **kwargs: object) -> list[str]:
    detector = PiiDetector(**kwargs)  # type: ignore[arg-type]
    return [d.rule_id for d in detector.detect(text)]


def test_email_is_detected() -> None:
    hits = _rule_ids("contact me at " + _INTERNAL_EMAIL + " please")
    assert hits == ["pii-email"]


def test_reserved_domain_email_is_not_flagged() -> None:
    assert _rule_ids("contact me at pat@example.com") == []
    assert _rule_ids("contact me at pat@sub.example.test") == []


def test_allowlisted_identity_email_is_not_flagged() -> None:
    detector = PiiDetector(identity_allow=("Pat Public <pat@example.org>",))
    assert detector.detect("pat@example.org is fine") == []


def test_nanp_555_range_phone_is_detected() -> None:
    hits = _rule_ids("call " + _NANP + " today", phone_regions=("US",))
    assert hits == ["pii-phone"]


def test_gb_ofcom_drama_range_phone_is_detected() -> None:
    hits = _rule_ids("call " + _GB_DRAMA + " today", phone_regions=("GB",))
    assert hits == ["pii-phone"]


def test_international_format_phone_is_always_detected() -> None:
    hits = _rule_ids("call " + _DE_INTL + " today", phone_regions=("US",))
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


def test_dotted_version_numbers_are_not_phone_numbers() -> None:
    assert _rule_ids("release 3.10.15.13 is out", phone_regions=("US", "GB", "DE")) == []
    assert _rule_ids("call " + _NANP_DOTTED + " today", phone_regions=("US",)) == ["pii-phone"]


def test_bare_digit_runs_are_not_phone_numbers() -> None:
    regions = ("US", "GB", "DE")
    for run in ("1687156", "12345678", "202555" + "0142", "4155550" + "123", "9876543210"):
        assert _rule_ids(f"size = {run}", phone_regions=regions) == [], run


def test_national_number_with_a_trunk_prefix_or_separator_is_detected() -> None:
    assert _rule_ids("call " + _GB_DRAMA, phone_regions=("GB",)) == ["pii-phone"]
    assert _rule_ids("call (202) 555-" + "0142", phone_regions=("US",)) == ["pii-phone"]
    assert _rule_ids("call 020" + "79460958", phone_regions=("GB",)) == ["pii-phone"]
    assert _rule_ids("call 1202555" + "0142", phone_regions=("US",)) == ["pii-phone"]


def test_bare_international_number_is_detected() -> None:
    assert _rule_ids("call +12025550" + "142", phone_regions=("GB",)) == ["pii-phone"]
