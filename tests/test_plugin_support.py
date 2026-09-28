"""Shared helpers for the plugin tests: read markdown for `go-public ...` invocations and
check them against the real Typer CLI (subcommand, flags, positional arity)."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any

import typer

from go_public.cli import app

CLICK_APP = typer.main.get_command(app)

_FENCE = re.compile(r"^\s*```")
_INLINE = re.compile(r"`([^`\n]+)`")
_TABLE_PIPE = re.compile(r"\\\|")


@dataclass(frozen=True)
class Invocation:
    line: int
    text: str
    fenced: bool


def code_snippets(markdown: str) -> list[Invocation]:
    """Every line of a fenced block and every inline code span, with 1-based line numbers."""
    found: list[Invocation] = []
    in_fence = False
    for number, raw in enumerate(markdown.splitlines(), start=1):
        if _FENCE.match(raw):
            in_fence = not in_fence
            continue
        if in_fence:
            if raw.strip():
                found.append(Invocation(number, raw.strip(), fenced=True))
            continue
        for match in _INLINE.finditer(raw):
            found.append(Invocation(number, _TABLE_PIPE.sub("|", match.group(1)), fenced=False))
    return found


def is_invocation(text: str, wrapper_prefixes: tuple[str, ...]) -> bool:
    """A snippet that starts with the wrapper or with a bare `go-public` word."""
    return text.startswith(wrapper_prefixes) or re.match(r"go-public(\s|$)", text) is not None


def tokens_after_program(text: str, wrapper_prefixes: tuple[str, ...]) -> list[str]:
    for prefix in wrapper_prefixes:
        if text.startswith(prefix):
            return shlex.split(text[len(prefix) :])
    return shlex.split(text)[1:]


# Typer vendors its own click; duck-type on `.commands` / `.param_type_name` instead of
# importing a click that may not be installed.
def is_group(command: Any) -> bool:
    return hasattr(command, "commands")


def _flag_table(command: Any) -> dict[str, Any]:
    table: dict[str, Any] = {}
    for param in command.params:
        if param.param_type_name == "option":
            for opt in [*param.opts, *param.secondary_opts]:
                table[opt] = param
    return table


def check_tokens(tokens: list[str], *, source: str = "", strict: bool = False) -> None:
    """Assert `tokens` (the arguments after `go-public`) name a real subcommand, only real
    flags, and a plausible number of positional arguments. `<placeholder>` tokens count as
    one value each. With `strict` a bare subcommand must still have its arguments."""
    where = f" in {source!r}" if source else ""
    command: Any = CLICK_APP
    index = 0
    while is_group(command) and index < len(tokens):
        token = tokens[index]
        if token.startswith("--"):
            break
        assert token in command.commands, f"{token!r} is not a go-public subcommand{where}"
        command = command.commands[token]
        index += 1
    if index == len(tokens) and not strict:
        return  # a bare mention such as `go-public show` in prose
    flags = _flag_table(command)
    positionals = 0
    rest = tokens[index:]
    position = 0
    while position < len(rest):
        token = rest[position]
        position += 1
        if token.startswith("--"):
            flag, has_value, _ = token.partition("=")
            assert flag in flags or flag in ("--help",), f"{flag!r} is not a flag here{where}"
            option = flags.get(flag)
            if option is not None and not option.is_flag and not has_value:
                assert position < len(rest), f"{flag!r} needs a value{where}"
                position += 1
        else:
            positionals += 1
    if is_group(command):
        return  # `go-public` alone, or a flag such as --version
    arguments = [p for p in command.params if p.param_type_name == "argument"]
    variadic = any(p.nargs == -1 for p in arguments)
    required = sum(1 for p in arguments if p.required)
    maximum = None if variadic else sum(max(p.nargs, 1) for p in arguments)
    assert positionals >= required, f"missing argument(s){where}"
    if maximum is not None:
        assert positionals <= maximum, f"too many arguments{where}"


def check_command_line(line: str) -> None:
    """`go-public export . --check`-style lines, as printed in the fix plan."""
    tokens = shlex.split(line)
    assert tokens[0] == "go-public", line
    check_tokens(tokens[1:], source=line, strict=True)
