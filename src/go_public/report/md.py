"""Markdown report (architecture.md "Report:"; product spec item 11)."""

from __future__ import annotations

from pathlib import Path

import jinja2

from go_public.model import Report

_ENV = jinja2.Environment(
    loader=jinja2.PackageLoader("go_public.report", "templates"),
    autoescape=False,
    trim_blocks=True,
    lstrip_blocks=True,
)
_ENV.filters["mdcell"] = lambda value: str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Report) -> str:
    return _ENV.get_template("report.md.j2").render(report=report)


def write_markdown(report: Report, path: Path) -> None:
    path.write_text(render_markdown(report), encoding="utf-8")
