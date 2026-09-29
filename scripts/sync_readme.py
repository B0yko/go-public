#!/usr/bin/env python3
"""Keep the generated blocks of README.md in sync with their sources.

The README holds blocks between marker comments::

    <!-- BEGIN generated:NAME -->
    ...
    <!-- END generated:NAME -->

Each block is rendered from a committed source and never edited by hand:

* result blocks come from `bench/results/*.md` (the files `go-public bench` writes),
  with the command, date, hardware, versions and detector commit taken from the same file;
* `config-reference` comes from the `Config` model in `src/go_public/config.py`;
* `self-scan-config` is the committed `.go-public.toml`.

Usage::

    python scripts/sync_readme.py           # rewrite README.md
    python scripts/sync_readme.py --check   # exit 1 if README.md is out of date
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
import types
import typing
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
RESULTS = ROOT / "bench" / "results"

_BLOCK_RE = re.compile(
    r"(?P<begin><!-- BEGIN generated:(?P<name>[a-z0-9-]+) -->)\n(?P<body>.*?)"
    r"(?P<end><!-- END generated:(?P=name) -->)",
    re.DOTALL,
)


# -- results files ---------------------------------------------------------------


@dataclass(frozen=True)
class Part:
    """One piece of a results file: the text of a section (tables included)."""

    section: str  # heading text; "" is the file's H1 section
    heading: str | None = None  # heading written in the README (level 4), if any
    details: str | None = None  # wrap the part in <details> with this summary


def _sections(text: str) -> dict[str, list[str]]:
    """Map heading text -> body lines. The H1 title maps to ''."""
    sections: dict[str, list[str]] = {}
    current = ""
    for line in text.splitlines():
        match = re.match(r"(#{1,6}) (.*)", line)
        if match:
            current = "" if len(match.group(1)) == 1 else match.group(2).strip()
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(line)
    return sections


def _strip_blank(lines: list[str]) -> list[str]:
    start, end = 0, len(lines)
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return lines[start:end]


def _meta(lines: list[str]) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in lines:
        match = re.match(r"- ([^:]+): (.*)", line)
        if match:
            meta[match.group(1).strip()] = match.group(2).strip()
    return meta


def render_part(sections: dict[str, list[str]], part: Part) -> str:
    if part.section not in sections:
        raise SystemExit(f"results file has no section {part.section!r}")
    lines = list(sections[part.section])
    if part.section == "":
        lines = [line for line in lines if not re.match(r"- [^:]+: ", line)]  # the header bullets
    text = "\n".join(_strip_blank(lines))
    if part.heading:
        text = f"#### {part.heading}\n\n{text}"
    if part.details:
        text = f"<details>\n<summary>{part.details}</summary>\n\n{text}\n\n</details>"
    return text


def provenance(meta: dict[str, str]) -> str:
    """The command that reproduces a table and the run it came from."""
    command = meta["Command"].strip("`")
    parts = [
        f"{meta['Date (UTC)'][:10]} (UTC)",
        meta["Hardware"],
        f"git {meta['git']}",
        f"go-public {meta['go-public']}",
        f"detector commit `{meta['Detector commit']}`",
    ]
    if "gitleaks" in meta:
        parts.append(f"gitleaks {meta['gitleaks']}")
    return f"```sh\n{command}\n```\n\nRun on " + "; ".join(parts) + "."


def results_block(stem: str, parts: list[Part]) -> str:
    text = (RESULTS / f"{stem}.md").read_text(encoding="utf-8")
    sections = _sections(text)
    chunks = [provenance(_meta(sections[""])), *(render_part(sections, p) for p in parts)]
    return "\n\n".join(chunks)


def _results(stem: str, *parts: Part) -> Callable[[], str]:
    return lambda: results_block(stem, list(parts))


# -- config reference ------------------------------------------------------------

#: One sentence per key. `tests/test_docs.py` fails if a key of the model has none.
KEY_DOCS: dict[str, str] = {
    "repo.path": (
        "Absolute path of the repository this config belongs to. `go-public init` writes it; "
        "a discovered config whose path names another repository is ignored with a warning."
    ),
    "identity.allow": (
        "Identities allowed in history, as `Name <email>`, `<email>` (any name) or `Name` "
        "(any email). They are not reported."
    ),
    "deny.terms": (
        "Organisation names, codenames, clients. Case-insensitive; variants are generated "
        "(`Acme Corp` also matches `acme-corp`, `acme_corp`, `acmecorp`, `AcmeCorp`) and a "
        "match needs a boundary on each side."
    ),
    "deny.domains": "Domains, including subdomains, email domains and URLs.",
    "deny.regex": "Raw regular expressions (RE2 syntax).",
    "deny.names": "People who must not appear. Searched like terms.",
    "deny.ticket_keys": "Ticket project keys: `FALCON` matches `FALCON-123`.",
    "secrets.gitleaks_config": (
        "Path to a gitleaks-format TOML to use instead of the bundled v8.30.1 rules "
        "(the `--gitleaks-config` flag does the same). Empty means the bundled rules."
    ),
    "secrets.generic_entropy": (
        "Minimum Shannon entropy, in bits per character, for go-public's own "
        "assignment-context detector (`generic-entropy`)."
    ),
    "secrets.generic_detector": "Turn that assignment-context detector on or off.",
    "pii.phone_regions": (
        "Default regions for phone numbers in national format. Numbers in international "
        "format are always detected."
    ),
    "pii.detect_names": (
        "Also search all content for the name of every identity in history that is not on "
        "`identity.allow` (the `--detect-names` flag does the same)."
    ),
    "paths.allowed_prefixes": (
        "Absolute-path prefixes that are not reported as local paths. Other absolute paths "
        "that reveal a user name are."
    ),
    "network.internal_suffixes": (
        "Host suffixes treated as internal hostnames. Hosts under a `deny.domains` entry "
        "are always flagged."
    ),
    "licence.owner": "Expected copyright holder. Other holders in licence files are reported.",
    "scan.max_scan_mb": (
        "Text blobs larger than this many MiB are not read; they are only reported as large files."
    ),
    "scan.jobs": "Worker processes for blob scanning. 0 means the CPU count.",
    "scan.fail_on": (
        "Lowest severity that makes `scan` exit 1 and blocks an export: `critical`, `high`, "
        "`medium`, `low` or `info`. The `--fail-on` flag overrides it."
    ),
    "files.sensitive_files": (
        "Globs for files that are sensitive by name (keys, `.env`, dumps, HTTP archives). "
        "Reported, and dropped from an export when `files.auto_exclude` is on."
    ),
    "files.internal_notes": (
        "Globs for notes and scratch files. Reported, and dropped from an export when "
        "`files.auto_exclude` is on."
    ),
    "files.warn_mb": "Blobs of at least this many MiB are reported as large files (low).",
    "files.high_mb": (
        "Blobs of at least this many MiB are reported at medium; a history export drops "
        "them. 100 MiB and above is high (GitHub refuses such files)."
    ),
    "files.auto_exclude": "Leave sensitive files and internal notes out of an export.",
    "trailers.flag": "Commit trailer keys to report, and to strip in a history export.",
    "allowlist.paths": (
        "Globs; a finding whose every path matches is suppressed (and listed in the report)."
    ),
    "allowlist.fingerprints": (
        "Suppressed findings, by finding fingerprint or group id, each with a reason. "
        "`go-public allow` appends here."
    ),
    "rotated.fingerprints": (
        "Secrets recorded as rotated, each with a reason. They show as done in group A and "
        "never suppress anything. `go-public allow --rotated` appends here."
    ),
    "export.author": (
        "Identity of the export commit, `Name <email>`. Required for an export; there is no "
        "fallback to your git config."
    ),
    "export.message": "Commit message of a squash export.",
    "export.date": '`"now"` or an ISO 8601 timestamp for the squash export commit.',
    "export.exclude": "Globs of paths left out of the export.",
    "export.strip_metadata": "Strip binary metadata (EXIF, PNG text, PDF info, OOXML fields).",
}

_LONG_LIST = 6


def _type_name(annotation: object) -> str:
    origin = typing.get_origin(annotation)
    if origin is list:
        (inner,) = typing.get_args(annotation)
        if isinstance(inner, type) and hasattr(inner, "model_fields"):
            fields = ", ".join(inner.model_fields)
            return f"list of {{{fields}}}"
        return f"list of {inner.__name__}"
    if origin in (typing.Union, types.UnionType):
        return " or ".join(_type_name(a) for a in typing.get_args(annotation))
    return str(getattr(annotation, "__name__", annotation))


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    return str(value)


def config_reference() -> str:
    sys.path.insert(0, str(ROOT / "src"))
    from go_public.config import Config

    rows = ["| Key | Type | Default | Meaning |", "|---|---|---|---|"]
    long_defaults: list[tuple[str, str, list[object]]] = []
    for table_name, table_field in Config.model_fields.items():
        model = table_field.annotation
        assert model is not None
        for key, field in model.model_fields.items():
            full = f"{table_name}.{key}"
            default = field.get_default(call_default_factory=True)
            if isinstance(default, list) and len(default) > _LONG_LIST:
                shown = "see below"
                long_defaults.append((table_name, key, default))
            elif isinstance(default, list) and not default:
                shown = "`[]`"
            elif isinstance(default, str) and default == "":
                shown = '`""`'
            else:
                shown = f"`{_toml_value(default)}`"
            meaning = KEY_DOCS[full].replace("|", "\\|")
            rows.append(f"| `{full}` | {_type_name(field.annotation)} | {shown} | {meaning} |")
    out = ["\n".join(rows), "", "Defaults of the long lists:", "", "```toml"]
    previous = ""
    for table_name, key, default in long_defaults:
        if table_name != previous:
            if previous:
                out.append("")
            out.append(f"[{table_name}]")
            previous = table_name
        items = ",\n".join(f"  {_toml_value(v)}" for v in default)
        out.append(f"{key} = [\n{items},\n]")
    out.append("```")
    return "\n".join(out)


def self_scan_config() -> str:
    text = (ROOT / ".go-public.toml").read_text(encoding="utf-8")
    tomllib.loads(text)  # must stay valid TOML
    return "```toml\n" + text.rstrip("\n") + "\n```"


# -- the blocks ------------------------------------------------------------------

BLOCKS: dict[str, Callable[[], str]] = {
    "config-reference": config_reference,
    "self-scan-config": self_scan_config,
    "results-synthetic": _results("synthetic-small-2-6", Part("")),
    "results-head-only": _results("head-only-compare-small-2-6", Part("")),
    "results-gitleaks": _results(
        "gitleaks-small-2-6",
        Part("Commands", "Commands"),
        Part("Recall by location type", "Recall by location type"),
        Part("Recall", "Recall"),
        Part("Wall time", "Wall time"),
        Part("Where the tools differ", "Where the tools differ"),
        Part("Blind-spot secrets", "Blind-spot secrets"),
    ),
    "results-export": _results(
        "export-verify-small-2-6",
        Part("squash", "Squash export"),
        Part("keep-history", "History-preserving export"),
    ),
    "results-real-world": _results(
        "real-world",
        Part("Repositories", "Repositories"),
        Part("Findings per 1,000 unique blobs", "Findings per 1,000 unique blobs"),
        Part("psf/requests: findings by rule (identity excluded)", details="psf/requests by rule"),
        Part(
            "pallets/flask: findings by rule (identity excluded)", details="pallets/flask by rule"
        ),
        Part("Tuning on these repositories", "Tuning on these repositories"),
        Part("Precision on a reviewed sample", "Precision on a reviewed sample"),
    ),
    "results-runtime": _results(
        "runtime",
        Part(""),
        Part("Synthetic medium fixture, seed 100", "Synthetic medium fixture"),
        Part("pallets/flask at 3.1.3 (real-world clone)", "pallets/flask 3.1.3"),
    ),
    "results-blind-spots": _results("blind-spots-small-0_1", Part("")),
}


def render(readme: str) -> str:
    names = [m.group("name") for m in _BLOCK_RE.finditer(readme)]
    unknown = sorted(set(names) - set(BLOCKS))
    if unknown:
        raise SystemExit(f"README has blocks with no renderer: {', '.join(unknown)}")
    missing = sorted(set(BLOCKS) - set(names))
    if missing:
        raise SystemExit(f"README is missing blocks: {', '.join(missing)}")

    def replace(match: re.Match[str]) -> str:
        body = BLOCKS[match.group("name")]()
        return f"{match.group('begin')}\n\n{body}\n\n{match.group('end')}"

    return _BLOCK_RE.sub(replace, readme)


def main(argv: list[str] | None = None) -> int:
    doc = (__doc__ or "").split("\n\n")[0]
    parser = argparse.ArgumentParser(description=doc)
    parser.add_argument("--check", action="store_true", help="fail if README.md is out of date")
    args = parser.parse_args(argv)
    current = README.read_text(encoding="utf-8")
    updated = render(current)
    if updated == current:
        print("README.md is in sync with bench/results and the config model")
        return 0
    if args.check:
        print("README.md is out of date: run `python scripts/sync_readme.py`", file=sys.stderr)
        return 1
    README.write_text(updated, encoding="utf-8")
    print("README.md updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
