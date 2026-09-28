"""`bench/negatives.py`: about 160 hard negatives per small seed, deterministic."""

from __future__ import annotations

import random

import pytest

from go_public.bench import negatives


def test_small_has_160_items_and_tiny_32(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def counting(path: str, item: negatives.Item) -> negatives.Item:
        def wrapped(rng: random.Random) -> str:
            calls.append(path)
            return item(rng)

        return wrapped

    wrapped = tuple((p, h, counting(p, i)) for p, h, i in negatives.KINDS)
    monkeypatch.setattr(negatives, "KINDS", wrapped)
    negatives.generate(random.Random(0), 10)
    assert len(calls) == 160
    calls.clear()
    negatives.generate(random.Random(0), 2)
    assert len(calls) == 32


def test_sixteen_kinds_one_file_each() -> None:
    files = negatives.generate(random.Random(0), 3)
    assert len(negatives.KINDS) == len(files) == 16
    assert len({path for path, _content in files}) == 16


def test_same_seed_same_negatives() -> None:
    assert negatives.generate(random.Random(5), 10) == negatives.generate(random.Random(5), 10)
    assert negatives.generate(random.Random(5), 10) != negatives.generate(random.Random(6), 10)


def test_order_numbers_are_never_phone_numbers() -> None:
    rng = random.Random(1)
    for _ in range(50):
        digits = negatives.non_phone_digits(rng)
        assert not negatives._looks_like_a_phone_number(digits)


def test_phone_valid_runs_are_phone_shaped_but_bare() -> None:
    rng = random.Random(2)
    for length in (7, 8, 9, 10):
        digits = negatives.phone_valid_digits(rng, length)
        assert len(digits) == length
        assert negatives._looks_like_a_phone_number(digits)


def test_lockfile_kind_holds_phone_valid_sizes() -> None:
    files = dict(negatives.generate(random.Random(0), 10))
    assert b"size = " in files["uv.lock"]
