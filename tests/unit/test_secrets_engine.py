"""`detect/secrets.py`: the ported gitleaks matching semantics plus the
generic-entropy detector. See docs/adr/0002-re2-and-ported-gitleaks-semantics.md.
"""

from __future__ import annotations

import random
from pathlib import Path

from go_public.detect.base import UnitCtx
from go_public.detect.gitleaks_config import load_gitleaks_config
from go_public.detect.secrets import SecretsEngine, shannon_entropy

from . import secret_tokens as tok

_RULE_FAMILIES = [
    ("aws-access-token", tok.aws_access_key, 'access_key = "{}"'),
    ("github-pat", tok.github_pat_classic, 'token = "{}"'),
    ("github-fine-grained-pat", tok.github_pat_fine_grained, 'token = "{}"'),
    ("gitlab-pat", tok.gitlab_pat, 'token = "{}"'),
    ("slack-bot-token", tok.slack_bot_token, 'token = "{}"'),
    ("slack-webhook-url", tok.slack_webhook_url, 'url = "https://{}"'),
    ("stripe-access-token", tok.stripe_secret_key, 'key = "{}"'),
    ("gcp-api-key", tok.google_api_key, 'key = "{}"'),
    ("sendgrid-api-token", tok.sendgrid_api_key, 'key = "{}"'),
    ("twilio-api-key", tok.twilio_api_key, 'key = "{}"'),
    ("npm-access-token", tok.npm_token, 'token = "{}"'),
    ("pypi-upload-token", tok.pypi_upload_token, 'token = "{}"'),
    ("shopify-access-token", tok.shopify_access_token, 'token = "{}"'),
    ("digitalocean-access-token", tok.digitalocean_token, 'token = "{}"'),
    ("private-key", tok.private_key_block, "{}"),
]

# A rule set with one rule whose regex can never match anything (the trailing `^^^`
# would need "unused" to end at text position 0). Used by the generic-entropy tests,
# which only care about the custom detector, not the vendored rules.
# Assembled at runtime: a keyword assignment with a random-looking value is what the
# generic detector flags in this repository's own self-scan.
_MIXED_12 = "aZ9kQ7" + "mN2pXb"

_NO_OP_RULE_CONFIG = '[[rules]]\nid = "unused"\nregex = "nomatch^^^"'


def _bundled_engine() -> SecretsEngine:
    return SecretsEngine(load_gitleaks_config())


def test_rule_families_detected_with_expected_rule_id() -> None:
    engine = _bundled_engine()
    rng = random.Random(1234)
    assert len(_RULE_FAMILIES) >= 10
    for rule_id, generate, template in _RULE_FAMILIES:
        value = generate(rng)
        text = template.format(value)
        detections = engine.detect(text, UnitCtx(path="config.txt"))
        ids = [d.rule_id for d in detections]
        assert rule_id in ids, f"{rule_id}: expected in {ids} for generated value"
        for d in detections:
            if d.rule_id == rule_id:
                assert d.category == "secret"
                assert d.secret is True
                assert d.severity == "critical"


def test_shannon_entropy_of_empty_string_is_zero() -> None:
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_uniform_higher_than_repeated() -> None:
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < shannon_entropy("aB3xQ9zK1mP7wT2n")


def test_keyword_prefilter_skips_rule_without_keyword_present() -> None:
    config = load_gitleaks_config(
        _write_config(
            """
        [[rules]]
        id = "kw-rule"
        regex = "[0-9]{6}"
        keywords = ["mustbepresent"]
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    # The regex would match "123456" on its own; the keyword gate must block it.
    assert engine.detect("value 123456", UnitCtx(path="a.txt")) == []
    hit = engine.detect("mustbepresent 123456", UnitCtx(path="a.txt"))
    assert [d.rule_id for d in hit] == ["kw-rule"]


def test_secret_group_extracts_inner_capture() -> None:
    config = load_gitleaks_config(
        _write_config(
            """
        [[rules]]
        id = "sg-rule"
        regex = '''prefix=(outer-(inner[0-9]{4}))'''
        secretGroup = 2
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    detections = engine.detect("prefix=outer-inner7788", UnitCtx(path="a.txt"))
    assert len(detections) == 1
    assert detections[0].value == "inner7788"


def test_secret_group_non_participating_optional_group_yields_empty_value() -> None:
    """Ports `FindStringSubmatch` semantics (detect.go): Go's non-participating
    capture groups are `""`, never absent — `finding.Secret = groups[r.SecretGroup]`
    sets an *empty* secret rather than dropping the finding. re2's Python binding
    returns `None` for a non-participating group, so the port must translate `None`
    to `""` to match gitleaks, instead of skipping the match outright.
    """
    config = load_gitleaks_config(
        _write_config(
            """
        [[rules]]
        id = "opt-rule"
        regex = "id=(a)?b"
        secretGroup = 1
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    detections = engine.detect("id=b", UnitCtx(path="a.txt"))
    assert len(detections) == 1
    assert detections[0].value == ""


def test_entropy_threshold_skips_low_entropy_match() -> None:
    config = load_gitleaks_config(
        _write_config(
            """
        [[rules]]
        id = "ent-rule"
        regex = "token=([a-zA-Z0-9]{12})"
        entropy = 3.0
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    assert engine.detect("token=aaaaaaaaaaaa", UnitCtx(path="a.txt")) == []
    hits = engine.detect("token=" + _MIXED_12, UnitCtx(path="a.txt"))
    assert len(hits) == 1


def test_allowlist_regex_target_secret_default() -> None:
    config = load_gitleaks_config(
        _write_config(
            """
        [[rules]]
        id = "rt-rule"
        regex = "secretvalue=([a-zA-Z0-9]{6,20})"
        [[rules.allowlists]]
        regexes = ['''^placeholder''']
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    assert engine.detect("secretvalue=placeholder1", UnitCtx(path="a.txt")) == []
    assert len(engine.detect("secretvalue=realvalue99", UnitCtx(path="a.txt"))) == 1


def test_allowlist_regex_does_not_match_empty_secret() -> None:
    """Ports `Allowlist.RegexAllowed` (allowlist.go): it short-circuits to `false`
    when the target string is empty, regardless of whether the configured regex
    itself matches an empty string (e.g. `.*`). Without that guard, a rule whose
    secretGroup captures nothing (see the non-participating-group port above) would
    be spuriously allowlisted by any `.*`-shaped regex.
    """
    config = load_gitleaks_config(
        _write_config(
            """
        [[rules]]
        id = "opt-rule2"
        regex = "id=(a)?b"
        secretGroup = 1
        [[rules.allowlists]]
        regexes = ['''.*''']
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    detections = engine.detect("id=b", UnitCtx(path="a.txt"))
    assert len(detections) == 1
    assert detections[0].value == ""


def test_allowlist_regex_target_line() -> None:
    config = load_gitleaks_config(
        _write_config(
            """
        [[rules]]
        id = "line-rule"
        regex = "secretvalue=([a-zA-Z0-9]{10})"
        [[rules.allowlists]]
        regexTarget = "line"
        regexes = ['''# *nosecret''']
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    assert engine.detect("secretvalue=realvalue99  # nosecret", UnitCtx(path="a.txt")) == []
    assert len(engine.detect("secretvalue=realvalue99", UnitCtx(path="a.txt"))) == 1


def test_allowlist_stopwords() -> None:
    config = load_gitleaks_config(
        _write_config(
            """
        [[rules]]
        id = "sw-rule"
        regex = "secretvalue=([a-zA-Z0-9]{10})"
        [[rules.allowlists]]
        stopwords = ["example"]
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    assert engine.detect("secretvalue=exampleval1", UnitCtx(path="a.txt")) == []
    assert len(engine.detect("secretvalue=realvalue99", UnitCtx(path="a.txt"))) == 1


def test_allowlist_condition_and_requires_both_path_and_regex() -> None:
    config = load_gitleaks_config(
        _write_config(
            """
        [[rules]]
        id = "and-rule"
        regex = "secretvalue=([a-zA-Z0-9]{10})"
        [[rules.allowlists]]
        condition = "AND"
        paths = ['''tests/fixtures/.*''']
        regexes = ['''^fixture''']
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    # Path matches but regex doesn't -> not allowed (AND requires both).
    assert len(engine.detect("secretvalue=realvalue99", UnitCtx(path="tests/fixtures/a.txt"))) == 1
    # Both match -> allowed.
    assert engine.detect("secretvalue=fixtureval1", UnitCtx(path="tests/fixtures/a.txt")) == []
    # Regex matches but path doesn't -> not allowed.
    assert len(engine.detect("secretvalue=fixtureval1", UnitCtx(path="other/a.txt"))) == 1


def test_allowlist_paths_skips_whole_fragment() -> None:
    config = load_gitleaks_config(
        _write_config(
            """
        [[allowlists]]
        paths = ['''vendor/.*''']

        [[rules]]
        id = "path-rule"
        regex = "secretvalue=([a-zA-Z0-9]{10})"
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    assert engine.detect("secretvalue=realvalue99", UnitCtx(path="vendor/lib.js")) == []
    assert len(engine.detect("secretvalue=realvalue99", UnitCtx(path="src/lib.js"))) == 1


def test_allowlist_commits_skips_whole_fragment() -> None:
    config = load_gitleaks_config(
        _write_config(
            """
        [[allowlists]]
        commits = ["deadbeef"]

        [[rules]]
        id = "commit-rule"
        regex = "secretvalue=([a-zA-Z0-9]{10})"
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    allowed_ctx = UnitCtx(path="a.txt", commit="deadbeef")
    other_ctx = UnitCtx(path="a.txt", commit="c0ffee")
    assert engine.detect("secretvalue=realvalue99", allowed_ctx) == []
    assert len(engine.detect("secretvalue=realvalue99", other_ctx)) == 1


def test_path_only_rule_matches_by_name() -> None:
    config = load_gitleaks_config(
        _write_config(
            r"""
        [[rules]]
        id = "p12-rule"
        path = '''(?i)(?:^|/)[^/]+\.p12$'''
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    hits = engine.detect("irrelevant content", UnitCtx(path="creds/bundle.p12"))
    assert len(hits) == 1
    assert hits[0].rule_id == "p12-rule"
    assert hits[0].extra.get("path_match") is True
    assert engine.detect("irrelevant content", UnitCtx(path="creds/bundle.pem")) == []


def test_required_rule_needs_both_parts_within_proximity() -> None:
    config = load_gitleaks_config(
        _write_config(
            """
        [[rules]]
        id = "part-b"
        regex = "id=([0-9]{6})"
        skipReport = true

        [[rules]]
        id = "part-a"
        regex = "secretvalue=([a-zA-Z0-9]{10})"
        [[rules.required]]
        id = "part-b"
        withinLines = 1
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    # part-b never reports on its own (skipReport).
    assert engine.detect("id=123456", UnitCtx(path="a.txt")) == []
    # part-a alone, no part-b nearby -> no finding (required rule not satisfied).
    assert engine.detect("secretvalue=realvalue99", UnitCtx(path="a.txt")) == []
    # both present within one line of each other -> part-a reports.
    text = "secretvalue=realvalue99\nid=123456\n"
    hits = engine.detect(text, UnitCtx(path="a.txt"))
    assert [d.rule_id for d in hits] == ["part-a"]


def test_generic_overlap_filter_drops_generic_when_vendor_rule_covers_same_secret() -> None:
    config = load_gitleaks_config(
        _write_config(
            """
        [[rules]]
        id = "specific-rule"
        regex = "specialtoken=([a-zA-Z0-9]{16,20})"

        [[rules]]
        id = "generic-broad-rule"
        regex = "=([a-zA-Z0-9]{16,20})"
        """
        )
    )
    engine = SecretsEngine(config, generic_detector_enabled=False)
    rng = random.Random(7)
    value = tok.generic_high_entropy_value(rng, 18)
    text = f"specialtoken={value}"
    hits = engine.detect(text, UnitCtx(path="a.txt"))
    ids = sorted(d.rule_id for d in hits)
    assert ids == ["specific-rule"]


def test_generic_entropy_detector_flags_high_entropy_assignment() -> None:
    config = load_gitleaks_config(_write_config(_NO_OP_RULE_CONFIG))
    engine = SecretsEngine(config, generic_entropy_threshold=4.3)
    rng = random.Random(2)
    value = tok.generic_high_entropy_value(rng, 32)
    text = f'api_secret = "{value}"\n'
    hits = engine.detect(text, UnitCtx(path="settings.py"))
    ids = [d.rule_id for d in hits]
    assert "generic-entropy" in ids
    for d in hits:
        if d.rule_id == "generic-entropy":
            assert d.severity == "high"


def test_generic_entropy_detector_skips_lockfile() -> None:
    config = load_gitleaks_config(_write_config(_NO_OP_RULE_CONFIG))
    engine = SecretsEngine(config, generic_entropy_threshold=4.3)
    rng = random.Random(3)
    value = tok.generic_high_entropy_value(rng, 32)
    text = f'"resolved" = "{value}"\n'
    assert engine.detect(text, UnitCtx(path="package-lock.json")) == []


def test_generic_entropy_detector_skips_long_lines() -> None:
    config = load_gitleaks_config(_write_config(_NO_OP_RULE_CONFIG))
    engine = SecretsEngine(config, generic_entropy_threshold=4.3)
    rng = random.Random(4)
    value = tok.generic_high_entropy_value(rng, 32)
    padded = "x" * 1001 + f' secret_key = "{value}"'
    assert engine.detect(padded, UnitCtx(path="settings.py")) == []


def test_generic_entropy_detector_skips_unquoted_module_attribute_references() -> None:
    config = load_gitleaks_config(_write_config(_NO_OP_RULE_CONFIG))
    engine = SecretsEngine(config, generic_entropy_threshold=3.0)
    code = (
        "\tauthr = urllib2.HTTPPasswordMgrWithDefaultRealm()\n"
        "\tauth_handler = ***REMOVED***(authr)\n"
    )
    assert engine.detect(code, UnitCtx(path="core.py")) == []
    # A quoted value of the same shape is still a candidate.
    quoted = 'auth_handler = "***REMOVED***"\n'
    assert [d.rule_id for d in engine.detect(quoted, UnitCtx(path="core.py"))] == [
        "generic-entropy"
    ]


_CFG_COUNTER = 0


def _write_config(text: str, tmp_dir: Path | None = None) -> Path:
    global _CFG_COUNTER
    _CFG_COUNTER += 1
    import tempfile

    base = tmp_dir or Path(tempfile.mkdtemp(prefix="gp-secrets-cfg-"))
    path = base / f"cfg-{_CFG_COUNTER}.toml"
    path.write_text(text)
    return path
