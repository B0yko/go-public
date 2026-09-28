# 7. git-filter-repo, run as a library in a child process, rewrites the kept history

## Context

`export --keep-history` has to produce a repository that keeps the branch's commits but
carries none of what the scan found: secrets in blobs and messages, sensitive files,
paths with a deny term, binary metadata, oversized blobs, personal identities and
trailers. That is a history rewrite. The options were `git filter-branch` (slow, unsafe
defaults, deprecated by git itself), BFG (Java, path and size oriented, no hooks for our
own value lists and metadata stripping), a hand-written `fast-export | fast-import`
filter, and git-filter-repo (MIT, on PyPI, exposes `RepoFilter` with blob, commit, tag
and filename callbacks). git-filter-repo is the maintained tool for this job and its
library interface fits: the callbacks receive the objects, so the metadata stripper of
the squash export and the literal replacement run in the same pass.

Version 2.47.0 is pinned; it was still the latest release when this was written.
Library usage follows the project README ("library usage") and the
`contrib/filter-repo-demos/barebones-example`: `FilteringOptions.parse_args(argv,
error_on_empty=False)` and `RepoFilter(args, blob_callback=..., commit_callback=...,
tag_callback=..., filename_callback=...).run()`.

## Decision

1. **Clone, then rewrite the clone.** The export runner clones the export ref's branch:
   `clone --no-local --single-branch --branch <b> --no-checkout [--no-tags]` with an
   empty template directory. Tags come only with `--include-tags`. A `--ref` that is not
   a branch exits 2. `--no-checkout` keeps the unfiltered files off disk; the final
   `reset --hard` of git-filter-repo writes the rewritten tree.
2. **Detach before filtering.** `config --remove-section remote.origin` (and the
   branch's tracking section), delete `refs/remotes/*`, delete tags whose name has a
   deny term, and rename the branch to `main` with `update-ref` and `symbolic-ref`
   (both on the export runner's allowlist). The source path never survives in config,
   refs or reflogs.
3. **One child process.** `python -P -m go_public.export._filter_child` runs with the
   clone as working directory. `-P` keeps the clone, whose files come from the audited
   repository, off `sys.path`. Its environment is the export runner's environment
   (`GitRunner.child_env`): no global or system git config, no inherited `GIT_*`, no
   hooks. The specification (identity, mailmap path, values, paths, limits) is one JSON
   document on stdin; literal values are never in argv or on disk. `--force` is passed
   because we made the clone ourselves and removed its remote, which git-filter-repo's
   fresh-clone check would refuse.
   **This child is the only git access outside `GitRunner`**: git-filter-repo starts its
   own `git fast-export`, `fast-import`, `reset`, `reflog expire` and `gc`. The static
   guard allows subprocess use in `export/` for it, and the immutability test covers this
   mode.
4. **What the callbacks do.**
   - Blobs: dropped at or above `[files] high_mb`; stripped of binary metadata
     (the same in-memory functions as the squash export; a failure aborts, an unstripped
     blob never ships); then the literal values behind the findings of that source blob
     replaced by `***REMOVED***`, longest first, UTF-16 files re-encoded with their BOM.
   - Commits and tags: every author, committer and tagger becomes the export identity
     (or the `--mailmap` applies, and unmapped identities are then reported by the
     re-scan); trailers on `[trailers] flag` are removed; values behind message findings
     are replaced.
   - File names: an exact list of historical paths is dropped from every commit:
     `export.exclude` globs, sensitive and internal-notes files (auto-exclude), paths
     whose unsuppressed finding is a deny term, and a tracked config that holds a deny
     list.
5. **Values are keyed by the source object.** The parent scans the source and keeps the
   literal text of each unsuppressed finding privately (`Finding.raw_value`, a pydantic
   private attribute that no dump, schema or report contains). The child looks values up
   by `original_id` of the blob, commit or tag. A finding that is allowlisted therefore
   keeps its value where it was allowlisted, and a value is replaced only in objects that
   carried a finding.
6. **Pre-check.** The same rules as the squash export apply to the export ref. In
   addition, a path at the export ref that contains a deny term always blocks (whatever
   `--fail-on` says): the rewrite would otherwise remove a file the user still has. The
   user renames it at HEAD first.
7. **Cleanup and verification.** git-filter-repo expires reflogs and prunes. The parent
   removes `.git/filter-repo` (old-to-new id maps), then lists the object store and
   fails the export (`NOT CLEAN`, directory kept) if any source blob, commit or tag that
   carried a value is still in it; before failing it expires and prunes once more.
8. **Re-scan and exit decision** are those of the squash export (unreachable objects
   included, export identity implicitly allowed). Licence findings that are not at the
   export ref are licence history: listed in group D, kept as they were, and left out of
   the exit decision unless `--fail-on-licence`.

## Consequences

- Commit ids change and signatures are dropped (fast-export strips them). The README
  says so.
- Replacement is literal: a detected local-path prefix is replaced without the rest of
  the path, and a short name can also match inside a longer word. The re-scan is the
  check; anything a scan can see but a literal replacement cannot reach (text inside a
  compressed archive, base64) ends as `NOT CLEAN`.
- Blobs that are not text and not stripped (archives, unknown formats) are copied as
  they are, as in the squash export.
- Large blobs below `high_mb` and licence history stay by design. `bench
  --export-verify` lists them in their own column.
- A repository with tens of thousands of commits takes as long as git-filter-repo takes;
  nothing here is parallel.
