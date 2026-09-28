"""The fix plan (architecture.md "Fix plan"; product spec item 12).

`build_plan` takes the *kept* (post-suppression) findings and returns a `PlanModel`
plus a refined copy of those findings whose `fix` action is filled in per category —
`scan.py`'s own `_fix_for` only ever sets `rotate`/`none` (stage-3's own documented
deviation: "review-licence/decide-large-file-shaped per-category fix actions are
plan.py's job in stage 4"). Callers put the refined findings in `Report.findings` and
this module's `PlanModel` in `Report.plan`, so the two stay consistent (a group's
`action` always matches the fingerprints it lists).

Group membership (architecture.md):
- A: every secret finding, grouped by `group_id`.
- B: `present_at_export_ref` and category not in `{licence, large-file}`.
- C: not `present_at_export_ref` and category != `licence` (this also catches a
  large-file finding that only ever existed in history).
- D: `licence` category (any location) + `large-file` category at the export ref.
Secrets appear in A and in B or C, per their own `present_at_export_ref`.
"""

from __future__ import annotations

from collections import defaultdict

from go_public.model import (
    Finding,
    FixAction,
    PlanDecideItem,
    PlanEntryA,
    PlanFileGroup,
    PlanModel,
)

#: `strip` can remove exactly these binary-metadata rule families (product spec item
#: 16: JPEG/PNG/WebP/PDF/OOXML).
_STRIPPABLE_RULE_PREFIXES = ("exif-", "png-", "pdf-", "ooxml-")
_LARGE_FILE_DECIDE_RULE_IDS = frozenset(
    {"large-file-warn", "large-file-high", "large-file-github-limit"}
)

#: `export`/`strip` do not exist in the CLI yet (later stages); `next_commands` only
#: ever names a subcommand this stage actually ships, so the "every next command
#: exists in the CLI" test (stage-4.md) holds today rather than only once those later
#: stages land. Recorded as a deviation in STATUS.md.
_PLACEHOLDER_REASON = "describe how/why this was resolved"


def build_plan(
    findings: list[Finding], *, rotated_reasons: dict[str, str] | None = None
) -> tuple[PlanModel, list[Finding]]:
    """Return `(plan, refined_findings)`: `refined_findings` is `findings` with each
    entry's `fix` replaced by the category-appropriate action; `plan` groups
    `refined_findings` by fingerprint so both stay consistent."""
    rotated_reasons = rotated_reasons or {}
    buckets = {f.fingerprint: _bucket(f) for f in findings}
    refined = [_refine_fix(f, buckets[f.fingerprint]) for f in findings]

    a_entries = _group_a(refined, rotated_reasons)
    b_entries = _group_file(refined, buckets, "B")
    c_entries = _group_file(refined, buckets, "C")
    d_entries = _group_d(refined, buckets)
    identity_notes = _identity_notes(refined)
    next_commands = _next_commands(a_entries)

    plan = PlanModel(
        A=a_entries,
        B=b_entries,
        C=c_entries,
        D=d_entries,
        identity_notes=identity_notes,
        next_commands=next_commands,
    )
    return plan, refined


def _bucket(finding: Finding) -> str:
    if finding.category == "licence":
        return "D"
    if finding.category == "large-file":
        return "D" if finding.present_at_export_ref else "C"
    return "B" if finding.present_at_export_ref else "C"


def _refine_fix(finding: Finding, bucket: str) -> Finding:
    action = _fix_action_for(finding, bucket)
    if action is None:
        return finding
    return finding.model_copy(update={"fix": action})


def _fix_action_for(finding: Finding, bucket: str) -> FixAction | None:
    if finding.category == "secret":
        return None  # scan.py's own "rotate" already fits every bucket.
    if bucket == "C":
        return FixAction(
            action="removed-by-squash",
            text="Only found in history, messages, identities, trailers or other refs: "
            "a squash export (the default) never carries it forward.",
        )
    if bucket == "D":
        if finding.category == "licence":
            return FixAction(
                action="review-licence", text="Not a legal conclusion: review before publishing."
            )
        if finding.rule_id in _LARGE_FILE_DECIDE_RULE_IDS:
            return FixAction(
                action="decide-large-file",
                text="Decide whether to keep, exclude, or replace this blob.",
            )
        return FixAction(action="none")
    # bucket == "B": present at the export ref, category not in {licence, large-file}.
    if finding.category in ("sensitive-file", "internal-notes"):
        return FixAction(
            action="exclude", text="Add to [export] exclude (on by default via auto_exclude)."
        )
    if finding.rule_id.startswith(_STRIPPABLE_RULE_PREFIXES):
        return FixAction(action="strip", text="Run `go-public strip` on this file.")
    if finding.location.kind == "path":
        return FixAction(action="rename-path", text="Rename this path before exporting.")
    return FixAction(action="edit-line", text="Edit this line before exporting.")


def _group_a(findings: list[Finding], rotated_reasons: dict[str, str]) -> list[PlanEntryA]:
    by_group: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.category == "secret":
            by_group[finding.group_id].append(finding)

    entries = []
    for group_id, members in by_group.items():
        first = members[0]
        rotated_reason = rotated_reasons.get(group_id)
        entries.append(
            PlanEntryA(
                secret_id=group_id,
                rule_id=first.rule_id,
                preview=first.preview,
                occurrences=len(members),
                paths=sorted({p for m in members for p in m.location.paths}),
                commits=sorted({c for m in members for c in m.commits}),
                refs=sorted({r for m in members for r in m.refs}),
                present_at_export_ref=any(m.present_at_export_ref for m in members),
                status="rotated" if rotated_reason is not None else "open",
                rotated_reason=rotated_reason,
            )
        )
    return sorted(entries, key=lambda e: e.secret_id)


def _group_key(finding: Finding) -> str:
    if finding.location.paths:
        return finding.location.paths[0]
    return f"<{finding.location.kind}>"


def _group_file(
    findings: list[Finding], buckets: dict[str, str], bucket: str
) -> list[PlanFileGroup]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if buckets[finding.fingerprint] != bucket:
            continue
        for key in finding.location.paths or [_group_key(finding)]:
            grouped[key].append(finding)

    groups = []
    for key, members in grouped.items():
        actions = {m.fix.action for m in members}
        action = next(iter(actions)) if len(actions) == 1 else _priority_action(actions)
        fix_text = next((m.fix.text for m in members if m.fix.action == action and m.fix.text), "")
        groups.append(
            PlanFileGroup(
                key=key,
                is_path=not key.startswith("<"),
                categories=sorted({m.category for m in members}),
                findings=sorted({m.fingerprint for m in members}),
                action=action,
                fix_text=fix_text,
            )
        )
    return sorted(groups, key=lambda g: g.key)


#: When a group mixes actions, the most urgent one wins (rotate a secret before
#: anything else; deleting/excluding the whole file makes a line edit moot).
_ACTION_PRIORITY = ("rotate", "delete-file", "exclude", "strip", "rename-path", "edit-line")


def _priority_action(actions: set[str]) -> str:
    for action in _ACTION_PRIORITY:
        if action in actions:
            return action
    return "mixed"


def _group_d(findings: list[Finding], buckets: dict[str, str]) -> list[PlanDecideItem]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if buckets[finding.fingerprint] == "D":
            grouped[finding.category].append(finding)
    return [
        PlanDecideItem(category=category, findings=sorted({m.fingerprint for m in members}))
        for category, members in sorted(grouped.items())
    ]


def _identity_notes(findings: list[Finding]) -> list[str]:
    """Every non-allowlisted identity found in history: a squash export drops these
    entirely (identities are never `present_at_export_ref`); `--keep-history` maps
    them to the export identity or `--mailmap` instead of leaving them as-is, but
    they are worth a maintainer's own look before choosing that mode."""
    identities = {
        f.location.identity for f in findings if f.category == "identity" and f.location.identity
    }
    return sorted(identities)


def _next_commands(a_entries: list[PlanEntryA]) -> list[str]:
    commands = [
        f'go-public allow {entry.secret_id} --rotated --reason "{_PLACEHOLDER_REASON}"'
        for entry in a_entries
        if entry.status == "open"
    ]
    return commands
