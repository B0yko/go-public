"""`bench/negatives.py`: about 150 hard negatives per small seed, deterministic."""

from __future__ import annotations

import random

import pytest

from go_public.bench import negatives


def test_small_has_150_items_and_tiny_30(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def counting(path: str, item: negatives.Item) -> negatives.Item:
        def wrapped(rng: random.Random) -> str:
            calls.append(path)
            return item(rng)

        return wrapped

    wrapped = tuple((p, h, counting(p, i)) for p, h, i in negatives.KINDS)
    monkeypatch.setattr(negatives, "KINDS", wrapped)
    negatives.generate(random.Random(0), 10)
    assert len(calls) == 150
    calls.clear()
    negatives.generate(random.Random(0), 2)
    assert len(calls) == 30


def test_fifteen_kinds_one_file_each() -> None:
    files = negatives.generate(random.Random(0), 3)
    assert len(negatives.KINDS) == len(files) == 15
    assert len({path for path, _content in files}) == 15


def test_same_seed_same_negatives() -> None:
    assert negatives.generate(random.Random(5), 10) == negatives.generate(random.Random(5), 10)
    assert negatives.generate(random.Random(5), 10) != negatives.generate(random.Random(6), 10)


def test_order_numbers_are_never_phone_numbers() -> None:
    rng = random.Random(1)
    for _ in range(50):
        digits = negatives.non_phone_digits(rng)
        assert not negatives._looks_like_a_phone_number(digits)
