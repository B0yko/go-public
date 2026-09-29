"""Suppression.

A finding is suppressed when: its fingerprint or group_id is in
`[allowlist].fingerprints` (a reason is required in the config entry, never
generated here); every path of a `blob`/`path` finding matches `[allowlist].paths`
(gitwildmatch, same semantics as `detect/files.py`'s own specs); its identity is on
`[identity].allow` (a finding can carry an identity the config only allowlisted after
the finding was produced, e.g. `export`'s own implicit self-allow); or the finding's
own line of text contains a `go-public:allow <reason>` comment (a non-empty reason is
required in the text itself). `[rotated]` never suppresses anything — it only marks a
group-A entry done (`plan.py`'s job) — so it plays no part here.

Every suppressed finding is returned alongside the ones that survive, so `report/*`
can list `report.suppressed` (fingerprint, group_id, category, rule_id, source,
reason, pattern) for a full audit trail, so suppression stays auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pathspec
import re2

from go_public.config import Config
from go_public.detect.commit_meta import is_identity_allowed
from go_public.git.inventory import Inventory
from go_public.git.objects import CatFileBatch
from go_public.git.runner import GitRunner
from go_public.model import Finding

#: A non-empty reason is required in the comment itself
#: (inline `go-public:allow <reason>` comments).
_INLINE_RE = re2.compile(r"go-public:allow[ \t]+(\S.*\S|\S)")

#: "config-fingerprint" | "config-group" | "path-glob" | "inline-comment" | "identity-allow"
SuppressSource = str


@dataclass(frozen=True, slots=True)
class SuppressedFinding:
    fingerprint: str
    group_id: str
    category: str
    rule_id: str
    source: SuppressSource
    reason: str
    pattern: str | None = None


@dataclass(frozen=True, slots=True)
class SuppressResult:
    kept: list[Finding] = field(default_factory=list)
    suppressed: list[SuppressedFinding] = field(default_factory=list)


def _split_identity(identity: str) -> tuple[str, str]:
    """`"Name <email>"` -> `(name, email)`; a bare identity with no `<...>` is treated
    as an all-name, no-email value (`is_identity_allowed` still matches a
    name-only allow entry)."""
    name, sep, rest = identity.partition(" <")
    if not sep:
        return identity, ""
    return name, rest[:-1] if rest.endswith(">") else rest


def _line_text(
    finding: Finding,
    inventory: Inventory,
    runner: GitRunner,
    blob_cache: dict[str, str],
) -> str | None:
    """The one line of source text a finding's `line` points at, or `None` when the
    location kind carries no such line (a fresh git read only ever happens for a
    `blob`/`unreachable_blob` finding, and at most once per distinct blob)."""
    loc = finding.location
    if loc.line is None:
        return None
    text: str | None = None
    if loc.kind in ("blob", "unreachable_blob") and loc.blob:
        if loc.blob not in blob_cache:
            with CatFileBatch(runner) as batch:
                got = batch.get(loc.blob)
            content = got[1] if got is not None else b""
            blob_cache[loc.blob] = content.decode("utf-8", errors="replace")
        text = blob_cache[loc.blob]
    elif loc.kind == "commit_message" and loc.commit:
        commit_obj = inventory.commits.get(loc.commit)
        text = commit_obj.message if commit_obj is not None else None
    elif loc.kind == "tag_message" and loc.tag:
        tag_obj = inventory.tags.get(loc.tag)
        text = tag_obj.message if tag_obj is not None else None
    if text is None:
        return None
    lines = text.splitlines()
    if 1 <= loc.line <= len(lines):
        return lines[loc.line - 1]
    return None


def run(
    findings: list[Finding],
    config: Config,
    inventory: Inventory,
    runner: GitRunner,
) -> SuppressResult:
    fingerprint_reasons = {entry.id: entry.reason for entry in config.allowlist.fingerprints}
    path_spec = pathspec.PathSpec.from_lines("gitwildmatch", config.allowlist.paths)
    identity_allow = list(config.identity.allow)
    blob_cache: dict[str, str] = {}

    kept: list[Finding] = []
    suppressed: list[SuppressedFinding] = []

    for finding in findings:
        decision = _suppress_by_config(finding, fingerprint_reasons)
        if decision is None and config.allowlist.paths:
            decision = _suppress_by_path(finding, path_spec, config.allowlist.paths)
        if decision is None and finding.category == "identity" and finding.location.identity:
            decision = _suppress_by_identity(finding, identity_allow)
        if decision is None:
            line = _line_text(finding, inventory, runner, blob_cache)
            if line is not None:
                decision = _suppress_by_inline_comment(finding, line)
        if decision is not None:
            suppressed.append(decision)
        else:
            kept.append(finding)

    return SuppressResult(kept=kept, suppressed=suppressed)


def _suppress_by_config(
    finding: Finding, fingerprint_reasons: dict[str, str]
) -> SuppressedFinding | None:
    if finding.fingerprint in fingerprint_reasons:
        source = "config-fingerprint"
        matched = finding.fingerprint
    elif finding.group_id in fingerprint_reasons:
        source = "config-group"
        matched = finding.group_id
    else:
        return None
    return SuppressedFinding(
        fingerprint=finding.fingerprint,
        group_id=finding.group_id,
        category=finding.category,
        rule_id=finding.rule_id,
        source=source,
        reason=fingerprint_reasons[matched],
        pattern=matched,
    )


def _suppress_by_path(
    finding: Finding,
    path_spec: pathspec.PathSpec[pathspec.pattern.Pattern],
    raw_patterns: list[str],
) -> SuppressedFinding | None:
    if finding.location.kind not in ("blob", "path") or not finding.location.paths:
        return None
    checks = [path_spec.check_file(path) for path in finding.location.paths]
    if not all(check.include for check in checks):
        return None
    patterns = sorted({raw_patterns[c.index] for c in checks if c.index is not None})
    return SuppressedFinding(
        fingerprint=finding.fingerprint,
        group_id=finding.group_id,
        category=finding.category,
        rule_id=finding.rule_id,
        source="path-glob",
        reason="every path matches an [allowlist].paths entry",
        pattern=", ".join(patterns) or None,
    )


def _suppress_by_identity(finding: Finding, identity_allow: list[str]) -> SuppressedFinding | None:
    name, email = _split_identity(finding.location.identity or "")
    if not is_identity_allowed(name, email, identity_allow):
        return None
    return SuppressedFinding(
        fingerprint=finding.fingerprint,
        group_id=finding.group_id,
        category=finding.category,
        rule_id=finding.rule_id,
        source="identity-allow",
        reason="identity is on [identity].allow",
    )


def _suppress_by_inline_comment(finding: Finding, line: str) -> SuppressedFinding | None:
    match = _INLINE_RE.search(line)
    if match is None:
        return None
    reason = match.group(1).strip()
    if not reason:
        return None
    return SuppressedFinding(
        fingerprint=finding.fingerprint,
        group_id=finding.group_id,
        category=finding.category,
        rule_id=finding.rule_id,
        source="inline-comment",
        reason=reason,
    )
