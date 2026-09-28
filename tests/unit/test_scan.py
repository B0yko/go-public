"""`scan.py`: orchestration, attribution, worker-pool parity.

Repos here are built with plain `subprocess` git calls (conftest.py's `git`/
`init_repo`/`commit_file`), never through `GitRunner` (package code may not use
`subprocess` directly — conventions.md).
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import pytest

from go_public import scan
from go_public.config import Config, DenyConfig, IdentityConfig, TrailersConfig
from go_public.git.inventory import build, build_head_only
from go_public.git.objects import CatFileBatch
from go_public.git.runner import GitRunner
from go_public.model import Finding
from go_public.scan import ScanOptions

from ..conftest import commit_file, empty_commit, git, hash_blob, init_repo
from . import secret_tokens as tok

_COMMIT_ENV = {
    "GIT_AUTHOR_NAME": "Pat Public",
    "GIT_AUTHOR_EMAIL": "pat@example.com",
    "GIT_COMMITTER_NAME": "Pat Public",
    "GIT_COMMITTER_EMAIL": "pat@example.com",
}


def _env_at(date: str) -> dict[str, str]:
    return {**_COMMIT_ENV, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}


def _secret_finding(findings: list[Finding], rule_id: str) -> Finding:
    matches = [f for f in findings if f.rule_id == rule_id]
    assert len(matches) == 1, f"expected exactly one {rule_id} finding, got {matches}"
    return matches[0]


def test_blob_secret_is_found_and_attributed(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.aws_access_key(random.Random(1))
    commit_oid = commit_file(repo, "config.txt", f'access_key = "{token}"\n', "feat: add config")
    runner = GitRunner(repo, role="source")
    inventory = build(runner)

    findings = scan.run(runner, inventory)
    finding = _secret_finding(findings, "aws-access-token")

    assert finding.category == "secret"
    assert finding.location.kind == "blob"
    assert finding.location.paths == ["config.txt"]
    assert finding.commits == [commit_oid]
    assert finding.commits_total == 1
    assert "refs/heads/main" in finding.refs
    assert finding.present_at_export_ref is True
    assert token not in finding.preview
    assert finding.preview.startswith(token[:4])
    assert finding.fix.action == "rotate"


def test_secret_removed_from_head_is_not_present_at_export_ref(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.stripe_secret_key(random.Random(2))
    commit_file(repo, "leaked.txt", f'key = "{token}"\n', "feat: add key")
    git(repo, "rm", "-q", "leaked.txt")
    git(repo, "commit", "-q", "-m", "chore: remove key", env=_env_at("2024-01-02T00:00:00+00:00"))
    runner = GitRunner(repo, role="source")
    inventory = build(runner)

    findings = scan.run(runner, inventory)
    finding = _secret_finding(findings, "stripe-access-token")
    assert finding.present_at_export_ref is False


def test_commit_message_secret_is_found(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "README.md", "hello\n", "chore: init")
    token = tok.github_pat_classic(random.Random(3))
    oid = empty_commit(repo, f"chore: rotate token {token}")
    runner = GitRunner(repo, role="source")
    inventory = build(runner)

    findings = scan.run(runner, inventory)
    finding = _secret_finding(findings, "github-pat")

    assert finding.location.kind == "commit_message"
    assert finding.location.commit == oid
    assert finding.commits == [oid]
    assert finding.present_at_export_ref is False


def test_tag_message_secret_is_found(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "README.md", "hello\n", "chore: init")
    token = tok.slack_bot_token(random.Random(4))
    git(
        repo,
        "tag",
        "-a",
        "v1",
        "-m",
        f"release note: {token}",
        env=_env_at("2024-01-03T00:00:00+00:00"),
    )
    runner = GitRunner(repo, role="source")
    inventory = build(runner)

    findings = scan.run(runner, inventory)
    finding = _secret_finding(findings, "slack-bot-token")

    assert finding.location.kind == "tag_message"
    assert finding.refs == ["refs/tags/v1"]
    assert finding.present_at_export_ref is False


def test_show_secrets_reveals_the_full_value(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.npm_token(random.Random(5))
    commit_file(repo, "config.txt", f'token = "{token}"\n', "feat: add token")
    runner = GitRunner(repo, role="source")
    inventory = build(runner)

    masked = scan.run(runner, inventory)
    finding = _secret_finding(masked, "npm-access-token")
    assert token not in finding.preview

    revealed = scan.run(runner, inventory, ScanOptions(show_secrets=True))
    finding = _secret_finding(revealed, "npm-access-token")
    assert finding.preview == token


def test_unreachable_blob_only_scanned_with_include_unreachable(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "README.md", "hello\n", "chore: init")
    token = tok.shopify_access_token(random.Random(6))
    # A blob written but never added to any tree: reachable from no ref.
    oid = hash_blob(repo, f'token = "{token}"\n')

    runner = GitRunner(repo, role="source")
    default_inventory = build(runner)
    default_findings = scan.run(runner, default_inventory)
    assert not any(f.rule_id == "shopify-access-token" for f in default_findings)

    full_inventory = build(runner, include_unreachable=True)
    findings = scan.run(runner, full_inventory)
    finding = _secret_finding(findings, "shopify-access-token")
    assert finding.location.kind == "unreachable_blob"
    assert finding.location.blob == oid
    assert finding.commits == []
    assert finding.refs == []
    assert finding.present_at_export_ref is False


def test_utf16_blob_is_scanned_as_text(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.digitalocean_token(random.Random(7))
    content = f'token = "{token}"\n'.encode("utf-16")
    (repo / "config.txt").write_bytes(content)
    git(repo, "add", "config.txt")
    git(
        repo,
        "commit",
        "-q",
        "-m",
        "feat: add utf-16 config",
        env=_env_at("2024-01-04T00:00:00+00:00"),
    )

    runner = GitRunner(repo, role="source")
    inventory = build(runner)
    findings = scan.run(runner, inventory)
    _secret_finding(findings, "digitalocean-access-token")


def test_blob_content_is_read_from_git_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.gitlab_pat(random.Random(8))
    content = f'token = "{token}"\n'
    commit_file(repo, "a/config.txt", content, "feat: add a")
    # A second path with byte-identical content: same blob, two occurrences.
    commit_file(repo, "b/config.txt", content, "feat: add b")

    runner = GitRunner(repo, role="source")
    inventory = build(runner)

    calls: list[str] = []
    original_get = CatFileBatch.get

    def counting_get(self: CatFileBatch, oid: str) -> Any:
        calls.append(oid)
        return original_get(self, oid)

    monkeypatch.setattr(CatFileBatch, "get", counting_get)
    findings = scan.run(runner, inventory)
    finding = _secret_finding(findings, "gitlab-pat")
    assert sorted(finding.location.paths) == ["a/config.txt", "b/config.txt"]

    blob_calls = [oid for oid in calls if oid == finding.location.blob]
    assert len(blob_calls) == 1


def test_regex_matched_exactly_once_per_blob_with_several_occurrences(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A blob present at several (path, commit) occurrences still has its content
    matched by `scan_content` exactly once (stage-3a fix for the stage-2b deviation
    that re-ran the regexes once per occurrence)."""
    from go_public.detect.secrets import SecretsEngine

    repo = init_repo(tmp_path / "repo")
    token = tok.aws_access_key(random.Random(11))
    content = f'access_key = "{token}"\n'
    commit_file(repo, "a/config.txt", content, "feat: add a")
    commit_file(repo, "b/config.txt", content, "feat: add b")
    commit_file(repo, "c/config.txt", content, "feat: add c")

    runner = GitRunner(repo, role="source")
    inventory = build(runner)

    calls: list[str] = []
    original = SecretsEngine.scan_content

    def counting_scan_content(self: SecretsEngine, text: str) -> Any:
        calls.append(text)
        return original(self, text)

    monkeypatch.setattr(SecretsEngine, "scan_content", counting_scan_content)
    findings = scan.run(runner, inventory, ScanOptions(jobs=1))
    finding = _secret_finding(findings, "aws-access-token")
    assert sorted(finding.location.paths) == ["a/config.txt", "b/config.txt", "c/config.txt"]
    # 3 occurrences of the same blob content, but only one `scan_content` call for it
    # (the other calls are the 3 distinct commit messages, unrelated text units).
    assert calls.count(content) == 1


def test_jobs_one_and_jobs_four_give_identical_findings(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    rng = random.Random(9)
    generators = [
        tok.aws_access_key,
        tok.github_pat_classic,
        tok.gitlab_pat,
        tok.stripe_secret_key,
        tok.npm_token,
    ]
    for i, generate in enumerate(generators):
        commit_file(
            repo, f"secrets/{i}.txt", f'token = "{generate(rng)}"\n', f"feat: add secret {i}"
        )

    runner = GitRunner(repo, role="source")
    inventory = build(runner)

    findings_1 = scan.run(runner, inventory, ScanOptions(jobs=1))
    findings_4 = scan.run(runner, inventory, ScanOptions(jobs=4))

    fps_1 = sorted(f.fingerprint for f in findings_1)
    fps_4 = sorted(f.fingerprint for f in findings_4)
    assert fps_1 == fps_4
    assert len(fps_1) >= len(generators)


def test_head_only_scan_finds_secrets_at_the_export_tree(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.sendgrid_api_key(random.Random(10))
    commit_file(repo, "config.txt", f'key = "{token}"\n', "feat: add key")
    runner = GitRunner(repo, role="source")
    inventory = build_head_only(runner)

    findings = scan.run(runner, inventory)
    finding = _secret_finding(findings, "sendgrid-api-token")
    assert finding.location.paths == ["config.txt"]
    assert finding.present_at_export_ref is True


# -- stage 3a: pii/deny/paths_network/files/commit_meta units --------------------


def _only(findings: list[Finding], rule_id: str) -> Finding:
    matches = [f for f in findings if f.rule_id == rule_id]
    assert len(matches) == 1, f"expected exactly one {rule_id} finding, got {matches}"
    return matches[0]


def test_org_identifier_deny_term_in_path_name(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "acme-corp/readme.txt", "hello\n", "feat: add readme")
    runner = GitRunner(repo, role="source")
    inventory = build(runner)
    config = Config(deny=DenyConfig(terms=["Acme Corp"]))

    finding = _only(scan.run(runner, inventory, ScanOptions(config=config)), "deny-term")
    assert finding.category == "org-identifier"
    assert finding.location.kind == "path"
    assert finding.location.paths == ["acme-corp/readme.txt"]
    assert finding.present_at_export_ref is True


def test_org_identifier_deny_term_in_ref_name(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hello\n", "feat: a")
    git(repo, "branch", "acme-corp/experiment")
    runner = GitRunner(repo, role="source")
    inventory = build(runner)
    config = Config(deny=DenyConfig(terms=["Acme Corp"]))

    finding = _only(scan.run(runner, inventory, ScanOptions(config=config)), "deny-term")
    assert finding.category == "org-identifier"
    assert finding.location.kind == "ref_name"
    assert finding.location.ref == "refs/heads/acme-corp/experiment"
    assert finding.refs == ["refs/heads/acme-corp/experiment"]
    assert finding.present_at_export_ref is False


def test_sensitive_file_and_internal_notes_paths(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, ".env", "unused\n", "feat: add env")
    commit_file(repo, "internal/plan.md", "unused\n", "feat: add plan")
    runner = GitRunner(repo, role="source")
    inventory = build(runner)

    findings = scan.run(runner, inventory)
    sensitive = _only(findings, "sensitive-file")
    assert sensitive.severity == "critical"
    assert sensitive.location.paths == [".env"]
    notes = _only(findings, "internal-notes")
    assert notes.location.paths == ["internal/plan.md"]


def test_identity_not_on_allowlist_is_flagged_with_roles(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    other = {"name": "Alex Rivera", "email": "alex@colleague.example"}
    commit_file(repo, "a.txt", "hello\n", "feat: a", author=other)
    runner = GitRunner(repo, role="source")
    inventory = build(runner)
    config = Config(identity=IdentityConfig(allow=[]))

    finding = _only(scan.run(runner, inventory, ScanOptions(config=config)), "identity")
    assert finding.category == "identity"
    assert finding.location.kind == "identity"
    assert finding.location.identity == "Alex Rivera <alex@colleague.example>"
    assert sorted(finding.extra["roles"]) == ["author", "committer"]  # type: ignore[arg-type]
    assert finding.present_at_export_ref is False


def test_deny_term_in_identity_name_is_flagged(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    other = {"name": "Acme Corp Bot", "email": "bot@colleague.example"}
    commit_file(repo, "a.txt", "hello\n", "feat: a", author=other)
    runner = GitRunner(repo, role="source")
    inventory = build(runner)
    config = Config(deny=DenyConfig(terms=["Acme Corp"]))

    finding = _only(scan.run(runner, inventory, ScanOptions(config=config)), "deny-term")
    assert finding.category == "org-identifier"
    assert finding.location.kind == "identity"
    assert finding.location.identity == "Acme Corp Bot <bot@colleague.example>"


def test_allowlisted_identity_produces_no_finding(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hello\n", "feat: a")
    runner = GitRunner(repo, role="source")
    inventory = build(runner)
    config = Config(identity=IdentityConfig(allow=["Pat Public <pat@example.com>"]))

    findings = scan.run(runner, inventory, ScanOptions(config=config))
    assert not any(f.category == "identity" for f in findings)


def test_flagged_trailer_with_email_is_medium(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    message = "feat: add thing\n\nCo-authored-by: Alex Rivera <alex@colleague.example>\n"
    commit_file(repo, "a.txt", "hello\n", message)
    runner = GitRunner(repo, role="source")
    inventory = build(runner)
    config = Config(trailers=TrailersConfig(flag=["Co-authored-by"]))

    finding = _only(scan.run(runner, inventory, ScanOptions(config=config)), "trailer")
    assert finding.category == "trailer"
    assert finding.severity == "medium"
    assert finding.location.kind == "trailer"
    assert finding.location.field == "Co-authored-by"
    assert finding.present_at_export_ref is False


def test_non_utc_timezone_offset_is_info(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    env = {
        "GIT_AUTHOR_NAME": "Pat Public",
        "GIT_AUTHOR_EMAIL": "pat@example.com",
        "GIT_AUTHOR_DATE": "2024-01-01T00:00:00+02:00",
        "GIT_COMMITTER_NAME": "Pat Public",
        "GIT_COMMITTER_EMAIL": "pat@example.com",
        "GIT_COMMITTER_DATE": "2024-01-01T00:00:00+00:00",
    }
    (repo / "a.txt").write_text("hello\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", "feat: a", env=env)
    runner = GitRunner(repo, role="source")
    inventory = build(runner)

    finding = _only(scan.run(runner, inventory), "timezone-offset")
    assert finding.category == "timezone"
    assert finding.severity == "info"
    assert finding.extra["role"] == "author"


def test_tracked_config_with_deny_terms_is_critical(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, ".go-public.toml", '[deny]\nterms = ["Acme Corp"]\n', "chore: config")
    runner = GitRunner(repo, role="source")
    inventory = build(runner)

    finding = _only(scan.run(runner, inventory), "tracked-config-deny")
    assert finding.category == "config"
    assert finding.severity == "critical"
    assert finding.location.kind == "path"
    assert finding.location.paths == [".go-public.toml"]
    assert finding.present_at_export_ref is True
