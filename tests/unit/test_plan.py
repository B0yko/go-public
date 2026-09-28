"""`plan.py`: fix-plan groups A-D, fix-action refinement, identity notes."""

from __future__ import annotations

from go_public.model import Finding, FixAction, Location
from go_public.plan import build_plan

EXPORT_COMMANDS = ["go-public export . --check", "go-public export . --out ../public-export"]


def _finding(
    *,
    fingerprint: str,
    group_id: str = "g",
    category: str,
    rule_id: str,
    kind: str = "path",
    paths: list[str] | None = None,
    blob: str | None = None,
    line: int | None = None,
    identity: str | None = None,
    present_at_export_ref: bool = True,
    fix_action: str = "none",
) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        group_id=group_id,
        category=category,
        rule_id=rule_id,
        severity="high",
        title="t",
        location=Location(kind=kind, paths=paths or [], blob=blob, line=line, identity=identity),
        location_key="k",
        present_at_export_ref=present_at_export_ref,
        preview="preview",
        fix=FixAction(action=fix_action),
    )


def test_secret_findings_group_into_a_by_group_id() -> None:
    a = _finding(
        fingerprint="fp1",
        group_id="secret-1",
        category="secret",
        rule_id="aws",
        kind="blob",
        blob="b1",
        paths=["x.txt"],
        present_at_export_ref=True,
        fix_action="rotate",
    )
    b = _finding(
        fingerprint="fp2",
        group_id="secret-1",
        category="secret",
        rule_id="aws",
        kind="blob",
        blob="b2",
        paths=["y.txt"],
        present_at_export_ref=False,
        fix_action="rotate",
    )

    plan, refined = build_plan([a, b])

    assert len(plan.A) == 1
    entry = plan.A[0]
    assert entry.secret_id == "secret-1"
    assert entry.occurrences == 2
    assert entry.present_at_export_ref is True  # any() of the two
    assert entry.status == "open"
    assert set(entry.paths) == {"x.txt", "y.txt"}
    # secrets also appear in B (present) and C (not present)
    assert any(fp in g.findings for g in plan.B for fp in ["fp1"])
    assert any(fp in g.findings for g in plan.C for fp in ["fp2"])
    assert {f.fix.action for f in refined} == {"rotate"}


def test_rotated_group_reports_status_rotated_with_reason() -> None:
    finding = _finding(
        fingerprint="fp1",
        group_id="secret-1",
        category="secret",
        rule_id="aws",
        fix_action="rotate",
    )

    plan, _ = build_plan([finding], rotated_reasons={"secret-1": "rotated in vault"})

    assert plan.A[0].status == "rotated"
    assert plan.A[0].rotated_reason == "rotated in vault"


def test_licence_finding_always_goes_to_d() -> None:
    present = _finding(
        fingerprint="fp1",
        category="licence",
        rule_id="licence-proprietary",
        present_at_export_ref=True,
    )
    absent = _finding(
        fingerprint="fp2",
        category="licence",
        rule_id="licence-transition",
        present_at_export_ref=False,
    )

    plan, refined = build_plan([present, absent])

    assert plan.B == []
    assert plan.C == []
    assert len(plan.D) == 1
    assert plan.D[0].category == "licence"
    assert set(plan.D[0].findings) == {"fp1", "fp2"}
    assert {f.fix.action for f in refined} == {"review-licence"}


def test_large_file_at_head_goes_to_d_otherwise_c() -> None:
    at_head = _finding(
        fingerprint="fp1",
        category="large-file",
        rule_id="large-file-high",
        present_at_export_ref=True,
    )
    history_only = _finding(
        fingerprint="fp2",
        category="large-file",
        rule_id="large-file-warn",
        present_at_export_ref=False,
    )

    plan, refined = build_plan([at_head, history_only])

    assert [d.category for d in plan.D] == ["large-file"]
    assert plan.D[0].findings == ["fp1"]
    assert any("fp2" in g.findings for g in plan.C)
    by_fp = {f.fingerprint: f for f in refined}
    assert by_fp["fp1"].fix.action == "decide-large-file"
    assert by_fp["fp2"].fix.action == "removed-by-squash"


def test_sensitive_file_at_head_action_is_exclude() -> None:
    finding = _finding(
        fingerprint="fp1",
        category="sensitive-file",
        rule_id="sensitive-file",
        paths=[".env"],
        present_at_export_ref=True,
    )

    plan, refined = build_plan([finding])

    assert plan.B[0].action == "exclude"
    assert refined[0].fix.action == "exclude"


def test_binary_metadata_at_head_action_is_strip() -> None:
    finding = _finding(
        fingerprint="fp1",
        category="binary-metadata",
        rule_id="exif-gps",
        kind="blob",
        blob="b1",
        paths=["photo.jpg"],
        present_at_export_ref=True,
    )

    plan, refined = build_plan([finding])

    assert refined[0].fix.action == "strip"
    assert plan.B[0].action == "strip"


def test_path_kind_finding_at_head_action_is_rename_path() -> None:
    finding = _finding(
        fingerprint="fp1",
        category="org-identifier",
        rule_id="deny-term",
        kind="path",
        paths=["acme-internal/notes.txt"],
        present_at_export_ref=True,
    )

    plan, refined = build_plan([finding])

    assert refined[0].fix.action == "rename-path"
    assert plan.B[0].action == "rename-path"


def test_blob_kind_finding_at_head_action_is_edit_line() -> None:
    finding = _finding(
        fingerprint="fp1",
        category="pii",
        rule_id="pii-email",
        kind="blob",
        blob="b1",
        line=3,
        paths=["a.txt"],
        present_at_export_ref=True,
    )

    plan, refined = build_plan([finding])

    assert refined[0].fix.action == "edit-line"
    assert plan.B[0].action == "edit-line"


def test_non_file_finding_groups_under_its_kind() -> None:
    finding = _finding(
        fingerprint="fp1",
        category="identity",
        rule_id="identity",
        kind="identity",
        identity="Colleague <c@example.com>",
        present_at_export_ref=False,
    )

    plan, _ = build_plan([finding])

    assert len(plan.C) == 1
    assert plan.C[0].key == "<identity>"
    assert plan.C[0].is_path is False
    assert plan.identity_notes == ["Colleague <c@example.com>"]


def test_next_commands_only_lists_open_secrets() -> None:
    open_secret = _finding(
        fingerprint="fp1",
        group_id="s1",
        category="secret",
        rule_id="aws",
        fix_action="rotate",
    )
    rotated_secret = _finding(
        fingerprint="fp2",
        group_id="s2",
        category="secret",
        rule_id="aws",
        fix_action="rotate",
    )

    plan, _ = build_plan([open_secret, rotated_secret], rotated_reasons={"s2": "done"})

    assert plan.next_commands[0].startswith("go-public allow s1 --rotated")
    assert sum(c.startswith("go-public allow") for c in plan.next_commands) == 1
    assert plan.next_commands[-2:] == EXPORT_COMMANDS


def test_empty_findings_produce_an_empty_plan() -> None:
    plan, refined = build_plan([])

    assert plan.A == plan.B == plan.C == plan.D == []
    assert plan.identity_notes == []
    assert plan.next_commands == EXPORT_COMMANDS
    assert refined == []


def test_next_commands_names_a_strip_line_per_strippable_path() -> None:
    finding = _finding(
        fingerprint="fp1",
        category="binary-metadata",
        rule_id="exif-gps",
        kind="blob",
        blob="b1",
        paths=["photo.jpg"],
        present_at_export_ref=True,
    )

    plan, _ = build_plan([finding])

    assert plan.next_commands == ["go-public strip photo.jpg", *EXPORT_COMMANDS]


def test_ooxml_comment_and_revision_authors_are_not_marked_strip() -> None:
    for rule_id in ("ooxml-comment-author", "ooxml-revision-author"):
        finding = _finding(
            fingerprint=f"fp-{rule_id}",
            category="binary-metadata",
            rule_id=rule_id,
            kind="binary_field",
            paths=["doc.docx"],
            present_at_export_ref=True,
        )

        plan, refined = build_plan([finding])

        assert refined[0].fix.action == "edit-line"
        assert plan.B[0].action == "edit-line"
