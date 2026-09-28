"""`detect/deny.py`: terms with variants, domains, raw regexes, ticket keys."""

from __future__ import annotations

from go_public.detect.deny import DenyDetector


def test_term_variants_are_all_detected() -> None:
    detector = DenyDetector(terms=("Acme Corp",))
    text = "acme-corp, acme_corp, acmecorp, Acme Corp all refer to the same place"
    hits = [d.value.lower() for d in detector.detect(text)]
    assert sorted(hits) == sorted(["acme-corp", "acme_corp", "acmecorp", "acme corp"])


def test_boundary_rule_matches_camel_case() -> None:
    detector = DenyDetector(terms=("Acme Corp",))
    hits = detector.detect("AcmeCorpClient connects to the API")
    assert len(hits) == 1
    assert hits[0].value == "AcmeCorp"


def test_boundary_rule_rejects_substring_word() -> None:
    detector = DenyDetector(terms=("Falcon",))
    assert detector.detect("falconry is a hobby") == []


def test_domain_and_subdomain_are_detected() -> None:
    detector = DenyDetector(domains=("buildhub.example",))
    hits = [d.value for d in detector.detect("see docs at sub.buildhub.example/api")]
    assert hits == ["sub.buildhub.example"]


def test_raw_regex_is_detected() -> None:
    detector = DenyDetector(regexes=(r"projx-\d{3}",))
    hits = [d.value for d in detector.detect("codename projx-942 launched")]
    assert hits == ["projx-942"]


def test_ticket_key_is_detected() -> None:
    detector = DenyDetector(ticket_keys=("SPROCKET",))
    hits = [(d.rule_id, d.value) for d in detector.detect("see SPROCKET-482 for details")]
    assert hits == [("deny-ticket", "SPROCKET-482")]


def test_mit_licence_quoted_in_docs_is_not_flagged() -> None:
    # Hard negative: an unrelated deny-list has nothing to do with a quoted licence.
    detector = DenyDetector(terms=("Acme Corp",))
    assert detector.detect("Permission is hereby granted, free of charge, ...") == []
