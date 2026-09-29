"""`truth.jsonl`: what a correct scan of a fixture repository must find.

One line per plant: the plant's location type, where it was placed and which
findings a correct scan reports for it.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class ExpectedFinding(BaseModel):
    """One finding a plant must produce (a plant may require several)."""

    category: str
    eval_class: str
    kind: str
    key: dict[str, str | int]


class TruthEntry(BaseModel):
    """One planted line of `truth.jsonl`."""

    plant_id: str
    category: str
    eval_class: str | None = None
    location_type: str
    at_export_ref: bool
    rule_family: str | None = None
    expected: list[ExpectedFinding] = Field(default_factory=list)


def write_truth(path: Path, entries: list[TruthEntry]) -> None:
    """Write one JSON object per line, in the given order."""
    lines = [entry.model_dump_json(exclude_none=True) for entry in entries]
    path.write_text("".join(line + "\n" for line in lines))


def read_truth(path: Path) -> list[TruthEntry]:
    """Read `truth.jsonl` back into `TruthEntry` objects."""
    text = path.read_text()
    return [TruthEntry.model_validate_json(line) for line in text.splitlines() if line.strip()]
