"""Offline by design: the integration suite runs with Python
socket connects patched to raise (`conftest.py`), and this checks the guard itself and
that whole commands finish under it."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from go_public.cli import app

from ..conftest import commit_file, init_repo
from .conftest import NetworkAttempt

runner = CliRunner()


def test_the_guard_refuses_connections() -> None:
    with pytest.raises(NetworkAttempt):
        socket.create_connection(("127.0.0.1", 9))
    with pytest.raises(NetworkAttempt):
        socket.socket().connect(("127.0.0.1", 9))
    with pytest.raises(NetworkAttempt):
        socket.getaddrinfo("example.com", 80)


def test_scan_export_show_and_strip_run_without_the_network(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    commit_file(repo, "a.txt", "hello\n", "feat: a")
    config = tmp_path / "c.toml"
    config.write_text('[identity]\nallow = ["Pat Public <pat@example.com>"]\n[scan]\njobs = 1\n')
    sample = tmp_path / "sample.txt"
    sample.write_text("x\n")

    results = [
        runner.invoke(
            app, ["scan", str(repo), "--config", str(config), "--report-dir", str(tmp_path / "r")]
        ),
        runner.invoke(app, ["show", str(repo), "a.txt", "--config", str(config)]),
        runner.invoke(app, ["strip", str(sample), "--check"]),
        runner.invoke(
            app,
            [
                "export",
                str(repo),
                "--out",
                str(tmp_path / "out"),
                "--author",
                "Pub Lic <pub@example.com>",
                "--config",
                str(config),
                "--report-dir",
                str(tmp_path / "r2"),
            ],
        ),
    ]

    for result in results:
        assert not isinstance(result.exception, NetworkAttempt), result.output
    assert [r.exit_code for r in results][1:] == [0, 0, 0]
