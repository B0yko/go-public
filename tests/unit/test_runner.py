"""GitRunner: per-role subcommand allowlists, environment, and error mapping."""

from __future__ import annotations

import pytest

from go_public.errors import GitError, UnsupportedRepo
from go_public.git.runner import GitRunner, RunnerViolation, check_git_version

ROLES = ["source", "export", "clone", "fixture"]


def test_check_git_version_ok() -> None:
    assert check_git_version(minimum=(2, 0)).startswith("git version")


def test_check_git_version_too_old() -> None:
    with pytest.raises(GitError):
        check_git_version(minimum=(999, 0))


@pytest.mark.parametrize("role", ROLES)
def test_forbidden_commands_always_blocked(role: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role=role)  # type: ignore[arg-type]
    for sub in ("push", "fetch", "remote"):
        with pytest.raises(RunnerViolation):
            runner._validate([sub])


READ_ONLY_SUBCOMMANDS = [
    "cat-file",
    "rev-list",
    "log",
    "for-each-ref",
    "ls-tree",
    "rev-parse",
    "show-ref",
    "count-objects",
]

ROLE_EXTRA_SUBCOMMANDS = {
    "source": [],
    "export": [
        "init",
        "hash-object",
        "update-index",
        "write-tree",
        "commit-tree",
        "update-ref",
        "checkout",
        "clone",
        "reflog",
        "gc",
    ],
    "clone": ["clone"],
    "fixture": ["init", "fast-import", "update-ref", "symbolic-ref", "hash-object"],
}


@pytest.mark.parametrize("role", ROLES)
def test_read_commands_pass_validation_for_every_role(role: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role=role)  # type: ignore[arg-type]
    for sub in READ_ONLY_SUBCOMMANDS:
        runner._validate([sub, "--dummy-arg"])


@pytest.mark.parametrize("role", ROLES)
def test_role_extra_commands_pass_validation(role: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role=role)  # type: ignore[arg-type]
    for sub in ROLE_EXTRA_SUBCOMMANDS[role]:
        runner._validate([sub])


def test_fixture_cannot_clone(tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role="fixture")
    with pytest.raises(RunnerViolation):
        runner._validate(["clone"])


def test_export_cannot_fast_import(tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role="export")
    with pytest.raises(RunnerViolation):
        runner._validate(["fast-import"])


def test_source_cannot_write(tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role="source")
    with pytest.raises(RunnerViolation):
        runner._validate(["commit-tree", "deadbeef"])


def test_source_config_only_with_get(tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role="source")
    runner._validate(["config", "--get", "user.name"])
    with pytest.raises(RunnerViolation):
        runner._validate(["config", "--get-all", "user.name"])
    with pytest.raises(RunnerViolation):
        runner._validate(["config", "user.name", "someone"])


def test_clone_config_only_with_get(tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role="clone")
    runner._validate(["config", "--get", "user.name"])
    with pytest.raises(RunnerViolation):
        runner._validate(["config", "user.name", "someone"])


@pytest.mark.parametrize("role", ["export", "fixture"])
def test_export_and_fixture_config_is_unrestricted(role: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role=role)
    runner._validate(["config", "user.name", "Pat Public"])
    runner._validate(["config", "--remove-section", "remote.origin"])


@pytest.mark.parametrize("role", ROLES)
def test_status_requires_porcelain(role: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role=role)
    runner._validate(["status", "--porcelain"])
    with pytest.raises(RunnerViolation):
        runner._validate(["status"])


def test_no_subcommand_is_a_violation(tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role="source")
    with pytest.raises(RunnerViolation):
        runner._validate(["--version"])


def test_log_always_gets_no_ext_diff_and_no_textconv() -> None:
    args = GitRunner._augment(["log", "--all"])
    assert args[0] == "log"
    assert "--no-ext-diff" in args
    assert "--no-textconv" in args


def test_log_augment_does_not_duplicate_existing_flags() -> None:
    args = GitRunner._augment(["log", "--no-ext-diff", "--all", "--no-textconv"])
    assert args.count("--no-ext-diff") == 1
    assert args.count("--no-textconv") == 1


def test_augment_leaves_other_commands_alone() -> None:
    args = GitRunner._augment(["rev-list", "--all"])
    assert args == ["rev-list", "--all"]


@pytest.mark.parametrize(
    "role,expected",
    [
        ("source", {"GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "none"}),
        ("export", {"GIT_ALLOW_PROTOCOL": "file"}),
        ("clone", {"GIT_ALLOW_PROTOCOL": "https"}),
        ("fixture", {"GIT_ALLOW_PROTOCOL": "none"}),
    ],
)
def test_role_specific_env(role: str, expected: dict[str, str], tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("GIT_DIR", "/should/be/dropped")
    monkeypatch.setenv("GIT_WORK_TREE", "/should/also/be/dropped")
    runner = GitRunner(tmp_path, role=role)
    env = runner._build_env(None)
    assert "GIT_DIR" not in env
    assert "GIT_WORK_TREE" not in env
    for key in (
        "LC_ALL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_TERMINAL_PROMPT",
        "GIT_PAGER",
        "GIT_OPTIONAL_LOCKS",
        "GIT_NO_REPLACE_OBJECTS",
    ):
        assert key in env
    assert env["LC_ALL"] == "C"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert env["GIT_PAGER"] == "cat"
    for key, value in expected.items():
        assert env[key] == value


def test_extra_env_overrides_base(tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role="source")
    env = runner._build_env({"LC_ALL": "en_US.UTF-8"})
    assert env["LC_ALL"] == "en_US.UTF-8"


def test_base_cmd_shape(tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role="source")
    cmd = runner._base_cmd()
    assert cmd[0] == "git"
    assert "-c" in cmd
    assert "core.quotepath=off" in cmd
    assert "core.fsmonitor=false" in cmd
    assert cmd[-2:] == ["-C", str(tmp_path)]


def test_not_a_git_repo_raises_unsupported_repo(tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role="source")
    with pytest.raises(UnsupportedRepo):
        runner.run(["rev-parse", "--is-bare-repository"])


def test_dubious_ownership_maps_to_unsupported_repo(tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role="source")
    with pytest.raises(UnsupportedRepo):
        runner._raise_for_failure(
            ["status", "--porcelain"],
            128,
            b"fatal: detected dubious ownership in repository at '/x'",
        )


def test_generic_git_failure_is_git_error(tmp_path) -> None:  # type: ignore[no-untyped-def]
    runner = GitRunner(tmp_path, role="source")
    with pytest.raises(GitError):
        runner._raise_for_failure(
            ["cat-file", "-p", "deadbeef"], 128, b"fatal: bad object deadbeef"
        )
