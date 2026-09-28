"""`model.py`: fingerprint/group_id formulas and the Finding/Location shapes."""

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from go_public.model import (
    Finding,
    FixAction,
    Location,
    make_fingerprint,
    make_group_id,
    severity_rank,
    sha256_hex,
)


def test_sha256_hex_matches_stdlib() -> None:
    assert sha256_hex("abc") == hashlib.sha256(b"abc").hexdigest()


def test_fingerprint_formula() -> None:
    rule_id, kind, location_key, value = "aws-access-token", "blob", "deadbeef:1:1", "AKIA..."
    expected = hashlib.sha256(
        "|".join([rule_id, kind, location_key, hashlib.sha256(value.encode()).hexdigest()]).encode()
    ).hexdigest()[:12]
    assert make_fingerprint(rule_id=rule_id, kind=kind, location_key=location_key, value=value) == (
        expected
    )


def test_fingerprint_differs_by_location_key() -> None:
    a = make_fingerprint(rule_id="r", kind="blob", location_key="b1:1:1", value="v")
    b = make_fingerprint(rule_id="r", kind="blob", location_key="b2:1:1", value="v")
    assert a != b


def test_group_id_formula() -> None:
    category, rule_id, value = "secret", "aws-access-token", "AKIA123"
    expected = hashlib.sha256(f"{category}|{rule_id}|{value}".encode()).hexdigest()[:12]
    assert make_group_id(category=category, rule_id=rule_id, normalized_value=value) == expected


def test_group_id_same_secret_two_locations_groups_together() -> None:
    a = make_group_id(category="secret", rule_id="r", normalized_value="same-secret")
    b = make_group_id(category="secret", rule_id="r", normalized_value="same-secret")
    assert a == b


def test_severity_rank_orders_critical_above_info() -> None:
    assert severity_rank("critical") > severity_rank("high") > severity_rank("info")


def test_finding_round_trips_through_model_validation() -> None:
    finding = Finding(
        fingerprint="abc123def456",
        group_id="fedcba987654",
        category="secret",
        rule_id="aws-access-token",
        severity="critical",
        title="Secret detected: aws-access-token",
        location=Location(kind="blob", blob="deadbeef", line=1, column=1),
        location_key="deadbeef:1:1",
        commits=["c1"],
        commits_total=1,
        refs=["refs/heads/main"],
        refs_total=1,
        present_at_export_ref=True,
        preview="AKIA…[len=20 sha256:aabbccdd]",
        fix=FixAction(action="rotate", text="Rotate this secret."),
        extra={"path_match": True},
    )
    dumped = finding.model_dump_json()
    restored = Finding.model_validate_json(dumped)
    assert restored == finding


def test_finding_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate(
            {
                "fingerprint": "a",
                "group_id": "b",
                "category": "secret",
                "rule_id": "r",
                "severity": "high",
                "title": "t",
                "location": {"kind": "blob"},
                "location_key": "k",
                "fix": {"action": "none"},
                "unknown_field": "nope",
            }
        )
