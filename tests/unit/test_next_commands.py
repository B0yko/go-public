"""`plan.py`'s `next_commands` (product spec item 12; stage-4.md): every line is an
exact `go-public` invocation whose subcommand and flags exist in the CLI.

`export`/`strip` don't exist yet (later stages), so `next_commands` only ever emits
`allow --rotated` lines today (STATUS.md deviation) — this test still validates the
general shape so it keeps holding once those commands land.
"""

from __future__ import annotations

import shlex

import typer

from go_public.cli import app
from go_public.model import Finding, FixAction, Location
from go_public.plan import build_plan

_CLICK_APP = typer.main.get_command(app)


def _assert_is_a_real_invocation(line: str) -> None:
    tokens = shlex.split(line)
    assert tokens[0] == "go-public"
    command = _CLICK_APP
    index = 1
    while hasattr(command, "commands"):
        name = tokens[index]
        assert name in command.commands, f"{name!r} is not a go-public subcommand"
        command = command.commands[name]
        index += 1
    known_flags = {opt for param in command.params for opt in param.opts}
    for token in tokens[index:]:
        if token.startswith("--"):
            flag = token.split("=", 1)[0]
            assert flag in known_flags, f"{flag!r} is not a flag of {tokens[index - 1]!r}"


def test_next_commands_only_names_flags_that_exist_in_the_cli() -> None:
    secret = Finding(
        fingerprint="fp1",
        group_id="grp1",
        category="secret",
        rule_id="aws-access-token",
        severity="critical",
        title="t",
        location=Location(kind="blob", blob="b1", line=1, column=1),
        location_key="b1:1:1",
        fix=FixAction(action="rotate"),
    )

    plan, _ = build_plan([secret])

    assert plan.next_commands  # the whole point of this test
    for line in plan.next_commands:
        _assert_is_a_real_invocation(line)


def test_no_open_secrets_means_no_next_commands() -> None:
    plan, _ = build_plan([])
    assert plan.next_commands == []
