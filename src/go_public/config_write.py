"""tomlkit-based config writes:
`go-public allow` appends fingerprint/rotated entries, `go-public init` writes a
fresh commented template. Both preserve an existing file's comments and formatting
(config writes use tomlkit, so comments survive), so every write
here goes through `tomlkit.parse`/`tomlkit.dumps`, never through `config.py`'s
`tomllib`-based reader.
"""

from __future__ import annotations

from pathlib import Path

import tomlkit
from tomlkit.exceptions import ParseError
from tomlkit.items import Array, Table

from go_public.errors import ConfigError, UsageError
from go_public.model import Report
from go_public.report.location import latest_report_dir


def load_document(path: Path) -> tomlkit.TOMLDocument:
    """The config at `path` as an editable `TOMLDocument`, or a fresh empty one when
    it does not exist yet."""
    if not path.exists():
        return tomlkit.document()
    try:
        return tomlkit.parse(path.read_text(encoding="utf-8"))
    except ParseError as exc:
        raise ConfigError(f"invalid TOML in config {path}: {exc}") from exc


def save_document(path: Path, doc: tomlkit.TOMLDocument) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(tomlkit.dumps(doc), encoding="utf-8")


def _table(doc: tomlkit.TOMLDocument, name: str) -> Table:
    existing = doc.get(name)
    if isinstance(existing, Table):
        return existing
    table = tomlkit.table()
    doc[name] = table
    return table


def _fingerprint_array(table: Table) -> Array:
    existing = table.get("fingerprints")
    if isinstance(existing, Array):
        return existing
    array = tomlkit.array()
    array.multiline(True)
    table["fingerprints"] = array
    return array


def append_allow_fingerprint(config_path: Path, fingerprint_or_group: str, reason: str) -> None:
    """`go-public allow <id> --reason "<text>"`: appends `{id, reason}` to
    `[allowlist].fingerprints`. `id` matches either a `Finding.fingerprint` or its
    `group_id` at suppression time (`suppress.py`), so either kind of id works here.
    """
    doc = load_document(config_path)
    entries = _fingerprint_array(_table(doc, "allowlist"))
    entry = tomlkit.inline_table()
    entry["id"] = fingerprint_or_group
    entry["reason"] = reason
    entries.append(entry)
    save_document(config_path, doc)


def append_rotated(config_path: Path, group_id: str, reason: str) -> None:
    """`go-public allow <id> --rotated --reason "<text>"`: records the secret's own
    `group_id` under `[rotated].fingerprints`. Never touches `[allowlist]`: a rotated
    secret still appears in group B/C, marked done only in group A (`plan.py`)."""
    doc = load_document(config_path)
    entries = _fingerprint_array(_table(doc, "rotated"))
    entry = tomlkit.inline_table()
    entry["id"] = group_id
    entry["reason"] = reason
    entries.append(entry)
    save_document(config_path, doc)


def load_latest_report(repo_name: str) -> Report:
    """The most recent `report.json` for `repo_name` (`report/location.py`'s
    `latest` symlink) — `allow --rotated` needs it to resolve a fingerprint/secret id
    to its `group_id` and to confirm it is actually a secret."""
    report_dir = latest_report_dir(repo_name)
    if report_dir is None:
        raise UsageError(f"no scan report found for {repo_name!r}; run `go-public scan` first")
    report_path = report_dir / "report.json"
    try:
        data = report_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot read report {report_path}: {exc}") from exc
    return Report.model_validate_json(data)


def resolve_secret_group_id(report: Report, fingerprint_or_group: str) -> str:
    """The `group_id` a secret `fingerprint_or_group` (a finding's own fingerprint,
    or already its group_id) resolves to in `report`. Raises `UsageError` (exit 2)
    when nothing matches, or when the match is not a secret finding (`--rotated` is
    refused for non-secret findings)."""
    for finding in report.findings:
        if fingerprint_or_group in (finding.fingerprint, finding.group_id):
            if finding.category != "secret":
                raise UsageError(
                    f"{fingerprint_or_group!r} is not a secret finding; "
                    "--rotated only applies to secrets"
                )
            return finding.group_id
    raise UsageError(
        f"no finding with fingerprint or secret id {fingerprint_or_group!r} in the latest report"
    )


#: `init`'s template: (table name, [(key, default, comment)]) in the order the file
#: should read in, matching `config.py`'s `Config` field order.
_TEMPLATE_TABLES: tuple[tuple[str, tuple[tuple[str, object, str], ...]], ...] = (
    ("identity", (("allow", [], 'e.g. ["Pat Public <pat@example.com>"]'),)),
    (
        "deny",
        (
            ("terms", [], "organisation names/abbreviations/client names/codenames"),
            ("domains", [], "internal or client domains"),
            ("regex", [], "raw regexes for anything else"),
            ("names", [], "people who must never appear (whole-word, case-insensitive)"),
            ("ticket_keys", [], 'project keys, e.g. ["FALCON"] matches FALCON-123'),
        ),
    ),
    ("licence", (("owner", "", "the copyright holder your LICENSE should name"),)),
    ("scan", (("fail_on", "high", "critical|high|medium|low|info"),)),
    ("export", (("author", "", 'required for export, e.g. "Pat Public <pat@example.com>"'),)),
)


def build_init_template(repo_path: Path, identities: list[str]) -> str:
    """A commented config template: `[repo] path` set to
    `repo_path`, every identity `init` found in history listed as a comment (never a
    live array entry — the user opts each one in), and every other table pre-filled
    with its default plus a one-line explanation."""
    doc = tomlkit.document()
    doc.add(tomlkit.comment("go-public config. Uncomment/edit what you need;"))
    doc.add(tomlkit.comment("every key here has a built-in default if you leave it out."))
    doc.add(tomlkit.nl())

    repo_table = tomlkit.table()
    repo_table["path"] = str(repo_path)
    doc["repo"] = repo_table
    doc.add(tomlkit.nl())

    if identities:
        doc.add(tomlkit.comment("Identities found in this repository's history:"))
        for identity in identities:
            doc.add(tomlkit.comment(f'  "{identity}"'))
        doc.add(tomlkit.comment("Add the ones that are yours to [identity] allow below."))
        doc.add(tomlkit.nl())

    for table_name, fields in _TEMPLATE_TABLES:
        table = tomlkit.table()
        for key, default, comment in fields:
            table[key] = default
            table[key].comment(comment)
        doc[table_name] = table
        doc.add(tomlkit.nl())

    return tomlkit.dumps(doc)
