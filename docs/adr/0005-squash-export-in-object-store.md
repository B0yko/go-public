# 5. Squash export is built directly in the export object store

## Context

The export must ship one clean commit and nothing else. Copying the working tree, or
using `git archive`, or cloning and then rewriting, all let something reach the
export that the export process did not choose: pre-strip bytes of an image, an
`export-ignore` or `export-subst` attribute silently changing content, hooks and
templates from the user's environment, a remote, or the user's own git identity.

## Decision

The squash export assembles the repository object by object, through the `export`
runner role only:

1. `git init --template=<empty temporary directory> --initial-branch=main`, then
   `commit.gpgsign=false`. There are no hooks and no inherited template.
2. Entries come from `ls-tree -r -z` at the export ref (not `git archive`). Only modes
   100644, 100755 and 120000 are kept. Gitlinks, `export.exclude` globs, sensitive and
   internal-notes files (unless `--no-auto-exclude`) and a tracked go-public config
   with deny entries are dropped.
3. Each kept blob is read from the source with `cat-file`, stripped of binary
   metadata in memory (unless `--no-strip`) and written with
   `hash-object -w --no-filters --stdin`. The pre-strip bytes are never written to
   the new object store. An unmodified file therefore keeps its source blob id, which
   the export checks.
4. `update-index --index-info` (with `GIT_INDEX_FILE` inside the export), `write-tree`,
   one `commit-tree` and `update-ref refs/heads/main`. Author and committer come only
   from `export.author` or `--author`; without one the export exits 2. The runner
   environment drops every inherited `GIT_*` variable and blocks global and system
   config, so the user's identity is never read.
5. The working tree is checked out from the new commit, no remote is configured, and
   the local `user.name` and `user.email` are set to the export identity unless
   `--no-set-identity`.
6. The export is re-scanned with unreachable objects included. Findings at or above
   `--fail-on` print `NOT CLEAN`, keep the directory and exit 1.

A pre-check runs first on the source at the export ref. It refuses (exit 1) when
findings at or above `--fail-on` remain that the export cannot resolve by itself
(`--force-export` overrides, `--check` runs only this step and writes nothing).
`--out` must not exist or be empty and must lie outside the source repository.

## Consequences

- Nothing is copied from the source object store, config or hooks, so the export has
  no way to carry over history, refs, stashes, notes or unreachable objects.
- Case-only path collisions stay in the commit; a warning is printed, because a
  case-insensitive file system holds only one of them.
- The cost is one `hash-object` process per unique kept blob (written from a thread
  pool), which is acceptable for a one-off export.
- A metadata stripper that fails on a file aborts the export instead of shipping the
  original bytes.
