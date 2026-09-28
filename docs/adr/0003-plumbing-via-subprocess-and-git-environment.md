# 3. Git access via subprocess plumbing, with a fixed environment

## Context

go-public reads every ref, commit, tag and blob in a repository's full history,
including refs a working-tree checkout never touches (`refs/stash`, `refs/replace/*`,
notes, remote-tracking refs). It needs raw object bytes (exact headers, encodings,
timezones) rather than git's pretty-printed summaries, and it must never trigger a
network operation, a hook, or a write to the repository it is auditing.

A binding such as pygit2 or GitPython would add a compiled dependency (libgit2) or a
porcelain-shaped API that hides exactly the raw-object and plumbing-command behaviour
this tool depends on, and neither gives the same fine-grained control over the
subprocess environment that git's own CLI does.

## Decision

Talk to git only through `subprocess`, wrapped in a single `GitRunner`
(`git/runner.py`). Every invocation is built as:

```
git -c core.quotepath=off -c core.fsmonitor=false [--git-dir=D] -C <repo> <subcommand> ...
```

`core.fsmonitor=false` matters because a repository's own config can name an
untrusted program to run as its filesystem monitor; `core.quotepath=off` keeps
non-ASCII paths readable instead of octal-escaped.

Every call also gets a fixed environment: `LC_ALL=C` (locale-independent output),
`GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=/dev/null` (the developer's or CI
runner's own git config never leaks in), `GIT_TERMINAL_PROMPT=0` (never blocks on a
credential prompt), `GIT_PAGER=cat` (no pager subprocess), `GIT_OPTIONAL_LOCKS=0`
(never contends with another git process on the same repo), `GIT_NO_REPLACE_OBJECTS=1`
(inventory sees the real objects, not `refs/replace/*` substitutions — those are
inventoried as a ref kind instead). Any inherited `GIT_*` variable (`GIT_DIR`,
`GIT_WORK_TREE`, `GIT_INDEX_FILE`, ...) is dropped before this fixed set is applied,
so a caller's shell environment cannot redirect where git reads or writes.

`git log` invocations always get `--no-ext-diff --no-textconv` appended by the runner
itself (not left to call sites to remember), so a repository's own `.gitattributes`
can never run an external diff or textconv filter as a subprocess.

## Consequences

- Zero extra compiled dependencies; the only requirement is a git binary new enough
  for `GIT_NO_LAZY_FETCH` and `for-each-ref`'s full namespace coverage (>= 2.44,
  checked at startup).
- Raw object parsing (`git/objects.py`) is go-public's own code, not a library's, so
  headers, encodings and multi-line values (e.g. `gpgsig`) are parsed exactly as
  needed for attribution and redaction, at the cost of writing that parser ourselves.
- Because every call goes through one function, the per-role allowlist in ADR 4 has
  a single enforcement point.
