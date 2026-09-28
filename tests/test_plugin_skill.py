"""The skill: frontmatter, the workflow's fixed rules, and every `go-public ...` invocation
in `skills/**` and `commands/**` (plus the next commands the fix plan prints) checked
against the real CLI."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import pytest

from go_public.model import Finding, FixAction, Location
from go_public.plan import build_plan
from tests.test_plugin_support import (
    CLICK_APP,
    Invocation,
    check_command_line,
    check_tokens,
    code_snippets,
    is_group,
    is_invocation,
    tokens_after_program,
)

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / "skills" / "go-public"
SKILL_MD = SKILL_DIR / "SKILL.md"
TRIAGE_MD = SKILL_DIR / "references" / "triage.md"

WRAPPER = '"${CLAUDE_PLUGIN_ROOT}/scripts/go-public"'
UNQUOTED_WRAPPER = "${CLAUDE_PLUGIN_ROOT}/scripts/go-public"
PREFIXES = (WRAPPER, UNQUOTED_WRAPPER)


def parse_frontmatter(text: str) -> tuple[dict[str, str | list[str]], str]:
    """The small YAML subset the skill uses: `key: value` and `key:` + `- item` lists."""
    match = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
    assert match, "SKILL.md must start with a frontmatter block"
    fields: dict[str, str | list[str]] = {}
    current: str | None = None
    for line in match.group(1).splitlines():
        if line.startswith("  - ") and current is not None:
            value = fields[current]
            assert isinstance(value, list)
            value.append(line[4:].strip())
            continue
        key, sep, value = line.partition(":")
        assert sep and key == key.strip() and re.fullmatch(r"[a-z][a-z-]*", key), line
        value = value.strip()
        if value == "":
            fields[key] = []
            current = key
        else:
            if value[0] in "\"'":
                assert value[-1] == value[0], f"unbalanced quotes in {key}"
                value = value[1:-1]
            else:
                # a plain YAML scalar must not contain ": " or " #"
                assert ": " not in value and " #" not in value, f"unquoted scalar in {key}"
            fields[key] = value
            current = None
    return fields, text[match.end() :]


def _skill_files() -> list[Path]:
    files = [p for p in (ROOT / "skills").rglob("*.md")]
    commands = ROOT / "commands"
    if commands.exists():
        files += list(commands.rglob("*.md"))
    return sorted(files)


def test_frontmatter_has_the_required_fields() -> None:
    fields, body = parse_frontmatter(SKILL_MD.read_text(encoding="utf-8"))
    assert fields["name"] == "go-public"
    description = fields["description"]
    assert isinstance(description, str) and 40 < len(description) <= 1536
    assert fields["argument-hint"] == "[repo-path]"
    assert "$ARGUMENTS" in body
    assert set(fields) <= {"name", "description", "argument-hint", "allowed-tools"}


def test_allowed_tools_are_scoped_to_the_wrapper_and_read_only_git() -> None:
    fields, _ = parse_frontmatter(SKILL_MD.read_text(encoding="utf-8"))
    tools = fields["allowed-tools"]
    assert isinstance(tools, list)
    assert "Bash(${CLAUDE_PLUGIN_ROOT}/scripts/go-public *)" in tools
    for rule in tools:
        assert re.fullmatch(
            r'Bash\("?\$\{CLAUDE_PLUGIN_ROOT\}/scripts/go-public"? \*\)|Bash\(git status \*\)', rule
        ), rule


def test_every_command_in_the_skill_goes_through_the_wrapper() -> None:
    for path in _skill_files():
        if path == TRIAGE_MD:
            continue
        for snippet in code_snippets(path.read_text(encoding="utf-8")):
            if snippet.fenced:
                assert not re.match(r"go-public(\s|$)", snippet.text), (
                    f"{path.name}:{snippet.line}: fenced command must use the wrapper"
                )
            first = snippet.text.split()[0] if snippet.text.split() else ""
            assert "scripts/go-public" not in first or first.strip('"') == UNQUOTED_WRAPPER, snippet


def _invocations(path: Path) -> list[Invocation]:
    return [
        s
        for s in code_snippets(path.read_text(encoding="utf-8"))
        if is_invocation(s.text, PREFIXES)
    ]


def test_every_invocation_in_the_skill_files_exists_in_the_cli() -> None:
    checked = 0
    for path in _skill_files():
        for snippet in _invocations(path):
            tokens = tokens_after_program(snippet.text, PREFIXES)
            if not tokens or tokens[0].startswith("<"):
                continue  # the generic `go-public <subcommand> ...` template
            tokens = [t for t in tokens if t != "..."]
            check_tokens(tokens, source=f"{path.name}:{snippet.line}: {snippet.text}")
            checked += 1
    assert checked >= 15


def test_every_flag_mentioned_in_code_exists_somewhere_in_the_cli() -> None:
    known: set[str] = set()

    def collect(command: Any) -> None:
        for param in command.params:
            if param.param_type_name == "option":
                known.update([*param.opts, *param.secondary_opts])
        if is_group(command):
            for sub in command.commands.values():
                collect(sub)

    collect(CLICK_APP)
    external = {"--public", "--source", "--push", "--mirror", "--short"}  # gh and git flags
    for path in _skill_files():
        for snippet in code_snippets(path.read_text(encoding="utf-8")):
            for flag in re.findall(r"(?<![\w-])--[a-z][a-z-]*", snippet.text):
                assert flag in known or flag in external, f"{path.name}:{snippet.line}: {flag}"


def test_the_workflow_names_all_eight_steps_in_order() -> None:
    body = SKILL_MD.read_text(encoding="utf-8")
    headings = re.findall(r"^### (\d)\. ", body, re.MULTILINE)
    assert headings == [str(n) for n in range(1, 9)]


def test_the_skill_encodes_the_fixed_rules() -> None:
    body = SKILL_MD.read_text(encoding="utf-8")
    lowered = body.lower()
    required = [
        "init <repo>",
        "scan <repo> --include-unreachable --summary-json",
        "allow <secret-id> --rotated --repo <repo> --reason",
        "show <repo> <path>",
        "redact <repo>/<path> --finding <secret-id> --with",
        "export <repo> --check",
        "scan <export-dir> --config <config-file> --include-unreachable --summary-json",
        "export <repo> --out <export-dir>",
        "gh repo create <name> --public --source <export-dir> --push",
        "never make the existing private repository public",
        "never amend, rebase, filter or force-push",
        "never delete it",
        "never pass `--show-secrets`",
        "never put report contents in commits, issues",
        "only when the user explicitly tells you to",
        "git ls-remote",
        "`refs/heads/main`",
        "does not replace rotating it",
    ]
    for needle in required:
        assert needle.lower() in lowered, needle
    # --show-secrets appears only in a sentence that forbids it
    for line in body.splitlines():
        if "--show-secrets" in line:
            assert "never" in line.lower(), line


def test_secret_carrying_files_are_never_opened_directly() -> None:
    body = SKILL_MD.read_text(encoding="utf-8")
    assert "never print, `cat`, `git show`" in body.lower()
    assert "read it yourself" not in body.lower().replace("do not read the file yourself", "")


def test_git_writes_are_left_to_the_user() -> None:
    fields, _ = parse_frontmatter(SKILL_MD.read_text(encoding="utf-8"))
    tools = fields["allowed-tools"]
    assert isinstance(tools, list)
    assert not any("commit" in t or "push" in t or "add" in t for t in tools)


@pytest.mark.parametrize("with_strip", [False, True])
def test_the_fix_plan_next_commands_exist_in_the_cli(with_strip: bool) -> None:
    findings = [
        Finding(
            fingerprint="fp1",
            group_id="grp1",
            category="secret",
            rule_id="aws-access-token",
            severity="critical",
            title="t",
            location=Location(kind="blob", blob="b1", paths=["a.txt"], line=1, column=1),
            location_key="b1:1:1",
            present_at_export_ref=True,
            fix=FixAction(action="rotate"),
        )
    ]
    if with_strip:
        findings.append(
            Finding(
                fingerprint="fp2",
                group_id="grp2",
                category="binary-metadata",
                rule_id="exif-gps",
                severity="high",
                title="t",
                location=Location(kind="binary_field", blob="b2", paths=["photo.jpg"]),
                location_key="b2:gps",
                present_at_export_ref=True,
                fix=FixAction(action="strip"),
            )
        )
    plan, _ = build_plan(findings)
    kinds = {shlex.split(line)[1] for line in plan.next_commands}
    assert {"allow", "export"} <= kinds
    if with_strip:
        assert "strip" in kinds
    for line in plan.next_commands:
        check_command_line(line)


def test_the_invocation_checker_rejects_bad_commands() -> None:
    for bad in (
        "go-public nonsense .",
        "go-public scan . --no-such-flag",
        "go-public scan",
        "go-public show only-one",
        "go-public allow abc --reason",
    ):
        with pytest.raises(AssertionError):
            check_command_line(bad)
    check_command_line('go-public allow abc --rotated --reason "text"')
    check_command_line("go-public rules check")
