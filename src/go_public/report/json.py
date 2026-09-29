"""JSON report: the `Report`
model, dumped straight to JSON — `schemas/go-public-report-v1.json` is generated from
the same model (`model.report_json_schema`).
"""

from __future__ import annotations

from pathlib import Path

from go_public.model import Report


def render_json(report: Report) -> str:
    return report.model_dump_json(indent=2) + "\n"


def write_json(report: Report, path: Path) -> None:
    path.write_text(render_json(report), encoding="utf-8")
