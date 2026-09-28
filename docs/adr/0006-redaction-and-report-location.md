# 6. Redact secrets by construction, and write reports outside the scanned tree

## Context

The report is the one artifact go-public hands back to a human, and it is built from
a private repository's own history — including, for group A, the exact values a
maintainer most needs kept out of a terminal scrollback, a screenshot or another
tool's logs. Product spec item 11 also requires that a report never reveal the
absolute path of the machine it ran on, and that writing it can never contaminate the
very repository being audited (a report file checked in by accident would be its own
finding on the next scan).

## Decision

Redaction happens once, in `redaction.py`, at the point a `Finding` is built
(`scan.py`), not in the report renderers: `preview` already carries either the full
value (`--show-secrets`) or `first 4 chars…[len=N sha256:prefix]`, so `report/json.py`,
`report/md.py` and `report/html.py` only ever print `finding.preview`, never
`finding.location`'s raw match data. A renderer that wanted the real value would have
to go out of its way to fetch it from git again; none of them do. The HTML renderer
also autoescapes every value (Jinja2's default for a `.html` template), since a
preview or path can still contain attacker-influenced bytes (a deny-term match, a
crafted file path) that must never become markup in a report a maintainer opens in a
browser — the Markdown renderer does not need this, since Markdown has no script
execution model.

The repository is named by directory only (`model.repo_display_name`, `.git` stripped
for a bare repo) everywhere in the report; nothing serializes `Config.repo.path` or
the CLI's own resolved absolute path. `report/location.py` writes outside the
scanned tree by construction: the default location is
`$XDG_STATE_HOME/go-public/<repo-name>/<UTC timestamp>/`, and `--report-dir` is
checked against the resolved scanned-repo path (`target == scanned_repo or
scanned_repo in target.parents`) before anything is written, refusing with the usual
usage-error exit code rather than writing partway and failing later. A `latest`
symlink at `<repo-name>/latest` always points at the newest report directory, which
`go-public allow --rotated` (`config_write.py`) reads back to resolve a fingerprint or
secret id to its group without asking the user to pass a report path around by hand.

## Consequences

- Every report renderer is trusted with only already-redacted strings; a bug that
  leaked a live secret into a report would have to be in `redaction.py`/`scan.py`,
  not in three separate template files that would each need to remember to redact.
- `--report-dir` still lets a user point reports at a path they choose (e.g. a CI
  artifact directory); only "inside the very tree being scanned" is refused, since
  that specific case is the one that would make the next scan see its own output.
- `latest` is best-effort (`report/location.py` swallows `OSError` from `symlink_to`):
  a filesystem without symlink support loses the "resolve by name" convenience for
  `allow --rotated`, never a scan.
