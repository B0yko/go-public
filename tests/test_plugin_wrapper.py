"""`scripts/go-public`: which go-public it runs, decided with a fake PATH so nothing real
(uv, the network, an installed go-public) is involved."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REAL_WRAPPER = ROOT / "scripts" / "go-public"
VERSION = "0.1.0"

PATH_BINARY = """#!/bin/sh
if [ "$1" = "--version" ]; then echo "go-public ${FAKE_PATH_VERSION:-0.1.0}"; exit 0; fi
echo "path-binary $*"
exit "${FAKE_EXIT:-0}"
"""

# Logs every call. A call fails when its arguments contain $FAKE_UVX_FAIL (a substring);
# a call that is not the `--version` probe exits with $FAKE_EXIT.
UV_RUNNER = """#!/bin/sh
echo "$0 $*" >> "$FAKE_LOG"
if [ -n "$FAKE_UVX_FAIL" ]; then
  case "$*" in *"$FAKE_UVX_FAIL"*) exit 2 ;; esac
fi
case "$*" in *"go-public --version"*) echo "go-public 0.0.0"; exit 0 ;; esac
echo "ran: $*"
exit "${FAKE_EXIT:-0}"
"""


@dataclass
class Sandbox:
    root: Path  # fake plugin root: scripts/go-public + .claude-plugin/plugin.json
    bin: Path  # the only directory on PATH (plus fakes put in it)
    log: Path

    @property
    def script(self) -> Path:
        return self.root / "scripts" / "go-public"

    def run(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        full_env = {
            "PATH": str(self.bin),
            "HOME": str(self.root),
            "FAKE_LOG": str(self.log),
            **env,
        }
        return subprocess.run(
            [str(self.script), *args], env=full_env, capture_output=True, text=True, timeout=60
        )

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []


def _executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def sandbox(tmp_path: Path) -> Sandbox:
    root = tmp_path / "plugin cache" / "go-public"  # a space in the path on purpose
    (root / "scripts").mkdir(parents=True)
    (root / ".claude-plugin").mkdir()
    shutil.copy2(REAL_WRAPPER, root / "scripts" / "go-public")
    (root / ".claude-plugin" / "plugin.json").write_text(
        f'{{\n  "name": "go-public",\n  "version": "{VERSION}"\n}}\n'
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("dirname", "sed", "head"):  # the only external tools the wrapper uses
        found = shutil.which(tool)
        assert found
        (bin_dir / tool).symlink_to(found)
    return Sandbox(root=root, bin=bin_dir, log=tmp_path / "calls.log")


def test_the_script_is_executable_posix_sh() -> None:
    assert os.access(REAL_WRAPPER, os.X_OK)
    assert REAL_WRAPPER.read_text().startswith("#!/bin/sh\n")
    assert subprocess.run(["sh", "-n", str(REAL_WRAPPER)]).returncode == 0
    assert "bash" not in REAL_WRAPPER.read_text().split("\n", 1)[0]


def test_git_tracks_the_executable_bit() -> None:
    listing = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-s", "scripts/go-public"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    if listing:  # empty before the first commit of the file
        assert listing.startswith("100755"), listing


def test_matching_version_on_path_is_used(sandbox: Sandbox) -> None:
    _executable(sandbox.bin / "go-public", PATH_BINARY)
    _executable(sandbox.bin / "uvx", UV_RUNNER)
    result = sandbox.run("scan", "some repo", "--summary-json")
    assert result.returncode == 0
    assert result.stdout == "path-binary scan some repo --summary-json\n"
    assert sandbox.calls() == []  # uvx never touched


def test_exit_code_of_the_path_binary_is_passed_through(sandbox: Sandbox) -> None:
    _executable(sandbox.bin / "go-public", PATH_BINARY)
    assert sandbox.run("scan", ".", FAKE_EXIT="1").returncode == 1


def test_version_mismatch_falls_back_to_uvx_from_the_plugin_root(sandbox: Sandbox) -> None:
    _executable(sandbox.bin / "go-public", PATH_BINARY)
    _executable(sandbox.bin / "uvx", UV_RUNNER)
    result = sandbox.run("scan", ".", FAKE_PATH_VERSION="0.0.9")
    assert result.returncode == 0
    assert "path-binary" not in result.stdout
    calls = sandbox.calls()
    assert len(calls) == 2  # probe, then the real call
    assert calls[0].endswith(f"--from {sandbox.root} go-public --version")
    assert calls[1].endswith(f"--from {sandbox.root} go-public scan .")


def test_no_go_public_on_path_uses_uvx(sandbox: Sandbox) -> None:
    _executable(sandbox.bin / "uvx", UV_RUNNER)
    assert sandbox.run("--version").returncode == 0
    assert sandbox.calls()[-1].endswith(f"--from {sandbox.root} go-public --version")


def test_uvx_failure_from_plugin_root_falls_back_to_the_tagged_release(sandbox: Sandbox) -> None:
    _executable(sandbox.bin / "uvx", UV_RUNNER)
    result = sandbox.run("scan", ".", FAKE_UVX_FAIL=f"--from {sandbox.root}")
    assert result.returncode == 0
    last = sandbox.calls()[-1]
    assert last.endswith(
        f"--from git+https://github.com/B0yko/go-public@v{VERSION} go-public scan ."
    )


def test_a_verdict_from_go_public_is_not_retried(sandbox: Sandbox) -> None:
    _executable(sandbox.bin / "uvx", UV_RUNNER)
    result = sandbox.run("scan", ".", FAKE_EXIT="1")
    assert result.returncode == 1
    assert not any("git+https" in call for call in sandbox.calls())
    assert len(sandbox.calls()) == 2


def test_nothing_starts_exits_126(sandbox: Sandbox) -> None:
    _executable(sandbox.bin / "uvx", UV_RUNNER)
    result = sandbox.run("scan", ".", FAKE_UVX_FAIL="go-public")
    assert result.returncode == 126
    assert "could not start go-public" in result.stderr


def test_uv_without_uvx_uses_uv_tool_run(sandbox: Sandbox) -> None:
    _executable(sandbox.bin / "uv", UV_RUNNER)
    assert sandbox.run("scan", ".").returncode == 0
    assert " tool run --from " in sandbox.calls()[-1]


def test_missing_uv_prints_install_instructions_and_exits_127(sandbox: Sandbox) -> None:
    _executable(sandbox.bin / "go-public", PATH_BINARY)
    result = sandbox.run("scan", ".", FAKE_PATH_VERSION="0.0.9")  # mismatch, so uv is needed
    assert result.returncode == 127
    assert "https://docs.astral.sh/uv/getting-started/installation/" in result.stderr
    assert result.stdout == ""


def test_the_version_comes_from_plugin_json(sandbox: Sandbox) -> None:
    (sandbox.root / ".claude-plugin" / "plugin.json").write_text(
        '{\n  "name": "go-public",\n  "version": "7.8.9"\n}\n'
    )
    _executable(sandbox.bin / "go-public", PATH_BINARY)
    assert sandbox.run("x").returncode == 127  # 0.1.0 on PATH no longer matches 7.8.9
    assert sandbox.run("x", FAKE_PATH_VERSION="7.8.9").stdout == "path-binary x\n"
    _executable(sandbox.bin / "uvx", UV_RUNNER)
    sandbox.run("x", FAKE_UVX_FAIL=f"--from {sandbox.root}", FAKE_PATH_VERSION="0.1.0")
    assert sandbox.calls()[-1].endswith("go-public@v7.8.9 go-public x")


def test_unreadable_plugin_json_exits_126(sandbox: Sandbox) -> None:
    (sandbox.root / ".claude-plugin" / "plugin.json").unlink()
    result = sandbox.run("scan", ".")
    assert result.returncode == 126
    assert "plugin version" in result.stderr


def test_the_wrapper_never_runs_itself_from_path(sandbox: Sandbox) -> None:
    # scripts/ on PATH: `command -v go-public` finds the wrapper, which must be skipped.
    _executable(sandbox.bin / "uvx", UV_RUNNER)
    (sandbox.bin / "go-public").symlink_to(sandbox.script)
    result = sandbox.run("scan", ".")
    assert result.returncode == 0
    assert sandbox.calls()[-1].endswith("go-public scan .")


def test_the_shipped_plugin_json_is_readable_by_the_wrapper(sandbox: Sandbox) -> None:
    shutil.copy2(ROOT / ".claude-plugin" / "plugin.json", sandbox.root / ".claude-plugin")
    real_version = (ROOT / "pyproject.toml").read_text().split('version = "', 1)[1].split('"', 1)[0]
    _executable(sandbox.bin / "go-public", PATH_BINARY)
    result = sandbox.run("x", FAKE_PATH_VERSION=real_version)
    assert result.stdout == "path-binary x\n"
