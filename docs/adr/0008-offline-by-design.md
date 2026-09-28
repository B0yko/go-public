# 8. Offline by design

## Context

A tool that audits a private repository for leaks must not be able to send anything
anywhere, and must not trigger a network fetch as a side effect of reading it. Two
routes exist: Python code opening sockets, and git subprocesses reaching a remote
(a partial clone's promisor remote, a `protocol.*.allow` setting, a credential helper
or a hook).

## Decision

- Product code makes no network call. There is no telemetry, update check or online
  lookup. The one exception is `go-public bench --real-world-dir`, which clones two
  pinned public repositories through a separate clone-only runner.
- Every git call goes through `GitRunner`. The `source` role sets
  `GIT_NO_LAZY_FETCH=1` and `GIT_ALLOW_PROTOCOL=none`, so a partial clone reports its
  missing objects (`rev-list --missing=print`) and never fetches them. The `export`
  role allows only the `file` protocol. `push`, `fetch` and `remote` are on no role's
  allowlist. All roles set `GIT_TERMINAL_PROMPT=0`, ignore global and system config
  and drop every inherited `GIT_*` variable.
- Tests enforce it in three places: the integration suite runs with `socket.socket`
  connect paths, `socket.create_connection` and `getaddrinfo` patched to raise; a
  partial-clone fixture whose promisor remote is unreachable (and one whose promisor
  `uploadpack` records any invocation) is scanned to a missing-object warning with no
  fetch attempt; and a static test asserts nothing in `src/` calls git with `push`.

## Consequences

- A scan of a partial clone is incomplete by design: missing blobs are reported as a
  warning and are not scanned. The user runs `git fetch` themselves if they want a
  full audit.
- Socket patching does not cover git subprocesses, which is why the environment
  restrictions and the partial-clone test exist as well.
- Publishing the export is left to the user; the tool prints the commands and does
  not run them.
