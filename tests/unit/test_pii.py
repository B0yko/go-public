"""`detect/pii.py`: emails, phone numbers and flagged names."""

from __future__ import annotations

from go_public.detect.pii import PiiDetector

# Plant-shaped strings are assembled at runtime (conventions.md).
_AT = chr(64)
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


# -- numeric data is not a phone number (found by scanning real repositories) -----------


def test_svg_path_data_is_not_a_phone_number() -> None:
    path = (
        'd="m 394.4689,161.155 c -1e-5,0.19141 -0.34864,0.48079 -1.0459,0.86816 '
        '0.38281 0.87956 c-2.35,11.81-7,23.46"'
    )
    assert _rule_ids(path) == []
    assert _rule_ids('<path d="M2.7207,-0.38281 c -0.25522,-0.0456 -0.61069,-0.11394"/>') == []


def test_decimal_and_probability_tables_are_not_phone_numbers() -> None:
    assert _rule_ids("  'mTypicalPositiveRatio': 0.982851,") == []
    assert _rule_ids("weights = [0.98285, 0.42718, 0.05012, 0.11394]") == []
    assert _rule_ids("x = 0.689-2.818") == []


def test_zip_plus_four_is_not_a_phone_number() -> None:
    assert _rule_ids("# 02110-1301  USA", phone_regions=("US", "GB")) == []


def test_candidate_glued_to_more_digits_is_not_a_phone_number() -> None:
    assert _rule_ids("id 1" + _NANP + "9", phone_regions=("US",)) == []
    assert _rule_ids("4.1" + _NANP, phone_regions=("US",)) == []


def test_phone_next_to_ordinary_punctuation_is_still_detected() -> None:
    assert _rule_ids("Call " + _NANP + ".", phone_regions=("US",)) == ["pii-phone"]
    assert _rule_ids("(" + _NANP + ") or " + _NANP_DOTTED + ", thanks", phone_regions=("US",)) == [
        "pii-phone",
        "pii-phone",
    ]
    assert _rule_ids("Tel: " + _GB_DRAMA + ";", phone_regions=("GB",)) == ["pii-phone"]


# -- URL credentials and scp-style remotes are not mailboxes ---------------------------------


def test_url_credentials_are_not_emails() -> None:
    assert _rule_ids('url = "http://user:pa' + "ss%20word" + _AT + 'complex.url.co"') == []
    assert _rule_ids("proxy_headers('http://user:pass@httpbin.org')") == []
    assert _rule_ids("remote = ssh://git@code-host.org/team/app.git") == []


def test_scp_style_remotes_are_not_emails() -> None:
    assert _rule_ids("git clone git@code-host.org:team/app.git") == []


def test_a_real_looking_email_near_a_url_is_still_flagged() -> None:
    mailbox = "jo" + "hn" + _AT + "corp-mail.org"
    assert _rule_ids("write to " + mailbox + " or see https://code-host.org/team") == ["pii-email"]
    assert _rule_ids("mailto:" + mailbox + ": thanks") == ["pii-email"]
    assert _rule_ids("https://code-host.org/contact?to=" + mailbox) == ["pii-email"]


def test_short_bare_constants_and_numeric_dates_are_not_phone_numbers() -> None:
    assert _rule_ids("mCount = 030304", phone_regions=("GB", "DE")) == []
    assert _rule_ids("2.10.0 (04-29-2016)", phone_regions=("US", "GB")) == []
    assert _rule_ids("released 2016-04-29 and 29-04-2016", phone_regions=("US", "GB")) == []
