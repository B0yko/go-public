"""Self-contained HTML report (architecture.md "Report:"; product spec item 11):
inline CSS/JS, a strict Content-Security-Policy, no network requests, filter by
category and severity, light and dark via `prefers-color-scheme`.

Autoescaping is on (unlike `report/md.py`): finding values/paths/previews come from
whatever the scanned repository's history contains, so this is untrusted content
rendered into HTML — Jinja2's autoescaping is what keeps a crafted blob (e.g. one
whose deny-term match is literally `<script>...`) from becoming a script in the
report a maintainer opens in a browser.
"""

from __future__ import annotations

from pathlib import Path

import jinja2

from go_public.model import Report

_ENV = jinja2.Environment(
    loader=jinja2.PackageLoader("go_public.report", "templates"),
    autoescape=jinja2.select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(report: Report) -> str:
    return _ENV.get_template("report.html.j2").render(report=report)


def write_html(report: Report, path: Path) -> None:
    path.write_text(render_html(report), encoding="utf-8")
