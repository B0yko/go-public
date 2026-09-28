"""Integration-suite guard: product spec item 18 (offline by design). Every test in
this directory runs with Python's socket connect paths patched to raise, so any code
path that would open a network connection fails the test. Git subprocesses are not
covered by this; `test_partial_clone.py` covers them separately."""

from __future__ import annotations

import socket
from collections.abc import Callable

import pytest


class NetworkAttempt(AssertionError):
    """Raised by the patched socket functions."""


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise NetworkAttempt("network access attempted during an offline-by-design test")

    refusing: dict[str, Callable[..., None]] = {
        "connect": refuse,
        "connect_ex": refuse,
    }
    for name, func in refusing.items():
        monkeypatch.setattr(socket.socket, name, func)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
