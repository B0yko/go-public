# 4. Read-only source runner; no code path can push

## Context

go-public's whole premise is that running it against a private repository is safe:
it audits history and proposes an export, but it must never modify, rewrite, or leak
the repository it is scanning. A single missing check — or a future contributor
copy-pasting an export command into the wrong place — could turn a read-only audit
tool into something that mutates the source repository or pushes it somewhere.

## Decision

`GitRunner` takes a `role` (`source`, `export`, `clone`, `fixture`) fixing both which
git subcommands it may run and the environment it runs them in (ADR 3). The `source`
role — the one bound to the repository being audited — allows only: `cat-file`,
`rev-list`, `log`, `for-each-ref`, `ls-tree`, `rev-parse`, `show-ref`,
`config --get` (never `--get-all` or a write form), `count-objects`, and
`status --porcelain`. `push`, `fetch` and `remote` are refused for every role, not
just `source`: nothing in go-public ever needs them, so there is no allowlist entry
to misuse. The source role also sets `GIT_NO_LAZY_FETCH=1` and
`GIT_ALLOW_PROTOCOL=none`, so a partial clone can never fetch a missing object and no
transport is available even if the repository's own config sets
`protocol.<name>.allow`.

A command outside a role's allowlist raises `RunnerViolation`, a `RuntimeError`
subclass distinct from the CLI's exit-code exceptions: a violation is always a bug in
go-public, never a condition a user can trigger, so it is never caught and mapped to
an exit code — it surfaces as a crash during development or CI.

Two tests hold this in place: a fingerprint test (source ref list, `count-objects -v`,
a hash of `.git/config`, `HEAD`, the index, and `git --no-optional-locks status
--porcelain`, taken before and after `scan`) must be identical before and after any
command runs, and a static test greps `src/go_public/` for the literal `"push"` /
`'push'` outside `git/runner.py` (where the forbidden-command set itself must name
it) and for `subprocess.run/Popen/call/check_call/check_output(` outside
`git/runner.py` (`export/` also shells out, for the `git-filter-repo` child process,
and `bench/`, for the real-world clone-only runner).

## Consequences

- The export and history-rewrite paths run in their own directories under their own
  roles (`export`, `fixture`); they never reuse a `source`-role runner, so a coding
  mistake that tried to write through the wrong runner fails immediately with a
  `RunnerViolation` rather than touching the source repository.
- Because the fingerprint test only needs to hold for `source`-role commands, the
  export and fixture roles remain free to write inside their own directories.
- `RunnerViolation` deliberately does not carry an exit code: turning it into a
  clean CLI error would make a real bug look like an ordinary user-facing failure.
