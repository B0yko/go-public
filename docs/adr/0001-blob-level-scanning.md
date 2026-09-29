# 1. Scan each unique blob once, not each commit's diff

## Context

A naive scanner walks every commit and re-scans whatever changed in its diff. Git
already gives every blob a content address (its sha1), so the same file content
committed at ten paths across ten commits, or copied once and never touched again,
is one object on disk — a diff-based walk would read and regex-match it up to ten
times over, and a long-lived repository can easily have orders of magnitude more
commits than unique blobs. Secrets, in particular, are pasted once and then often
copied verbatim (a config file forked into a second service, a `.env` committed
twice under different names), so the redundancy a diff-based walk pays for is
exactly the case a security scanner should expect, not a corner case.

Attribution still needs to answer commit- and ref-shaped questions — which commits
introduced a finding, which refs contain it, is it present at the export ref — so
scanning by blob does not remove the need to know a blob's occurrences; it only
changes *when* that mapping is built and *how many times* the blob's content itself
is matched against the rule set.

## Decision

`git/inventory.py` already produces the one artifact this needs for free:
one `git log --all --raw --no-renames --no-abbrev --diff-merges=separate -z` pass
gives every `(blob, path, commit)` occurrence in the whole reachable history, root
commits and merges included, without ever reading blob content itself. `scan.py`
scans each unique blob's content — via exactly one `cat-file` read per
blob, sharded across `--jobs` worker processes — and re-runs the already-compiled
detectors once per *distinct* `(path, commit)` occurrence of that blob, not once per
occurrence-content pair: a blob that occurs at one path in one commit (the common
case) is matched exactly once; a blob duplicated across several paths or reintroduced
by several commits is matched once per distinct pair, because a rule's own `path`
filter and a path- or commit-scoped allowlist entry (`detect/secrets.py`, ported from
gitleaks) can each only be evaluated correctly against a real `(path, commit)`. Two
occurrence-runs of the same blob that agree on `(rule_id, start)` are the same
underlying match — same content, same offset — and are merged into one finding whose
`paths`/`commits` lists hold exactly the occurrences where it survived allowlisting,
so a rule that only fires for a `.pem` path is attributed only to the `.pem` path
even when the identical bytes also live at a `.txt` path. Commit and tag messages,
identities, trailers, ref names and paths are separate scan units (`detect/base.py`'s
`TextUnit`) scanned in the main process, since they are already in memory from the
inventory build and need no `cat-file` read of their own; only blobs go through the
worker pool.

`--include-unreachable` folds in every blob the object database holds that the
history walk didn't already find (dangling and reflog-only objects, via `cat-file
--batch-all-objects`); those have no occurrences at all, so they are scanned once
with no path/commit context and attributed to no commit and no ref.

## Consequences

- A blob's content is read from git and matched against the rule set at most once
  per distinct occurrence, never once per commit that happens to contain it; the
  dominant real-world case (one blob, one path, one introducing commit) is exactly
  once overall — `tests/integration/test_scan_pipeline.py`-equivalent coverage in
  `tests/unit/test_scan.py::test_blob_content_is_read_from_git_exactly_once` asserts
  the `cat-file` read count, not the number of detector invocations, since those are
  allowed to differ when a blob has several distinct occurrences.
  `test_jobs_one_and_jobs_four_give_identical_findings` holds the sharding itself to
  the same guarantee: which worker happened to scan a blob never changes the result.
- Attribution (which commits, which refs, `present_at_export_ref`) is a property of
  the *occurrence*, computed from the inventory's own `(blob, path, commit)| table
  and `refs_containing` (lazy, cached per commit), not
  recomputed by re-diffing anything.
- The trade-off this buys is temporal: a blob's occurrences are known before any
  content is scanned, so a rename or a revert to identical bytes is attributed
  correctly for free, but a scan cannot report "which commit's diff introduced this
  line" in the sense of a line-level blame — only "which commits added or modified a
  blob containing it", which is what the product surfaces (fix plan groups, not a
  blame view).
- Messages/identities/trailers/ref names/paths never enter the worker pool: they are
  bounded by the number of commits and refs, not by blob size or count, and reusing
  the inventory's already-parsed `CommitObj`/`TagObj` avoids a second `cat-file`
  pass over the same objects the inventory build already read once.
