# 11. The plugin is one skill and a version-checked wrapper

## Context

The workflow (config, scan, rotate, fix, export, publish) needs a person in the loop at
each step, and the person's agent must never see a secret value. The plugin system now
treats skills as slash commands, exposes the plugin directory to skill text and
`allowed-tools` rules as a substitution variable (not in the environment of the commands
it runs), and may cache a plugin without its `.git` directory.

## Decision

- One skill, `skills/go-public/SKILL.md`, is the entry point (`/go-public [repo-path]`).
  There is no `commands/` directory, so no second entry point exists. The steps and the
  rules that keep secrets out of the agent's context are written in the skill body;
  category and rule-id triage lives in `references/triage.md`.
- Every call goes through `scripts/go-public` (POSIX sh). It runs a `go-public` from
  `PATH` only when `go-public --version` equals the plugin version read from
  the plugin manifest (`plugin.json`); otherwise `uvx --from <plugin root>`, then
  `uvx --from git+https://github.com/B0yko/go-public@v<version>`. It probes with
  `--version` before running, so a non-zero exit afterwards is go-public's own verdict.
  A missing `uv` prints the install instructions and exits 127; nothing starting exits
  126. `allowed-tools` pre-approves only this wrapper and `git status`.
- The version is static in `pyproject.toml`. A test requires it to agree with
  `plugin.json`, `marketplace.json` and `go-public --version`.
- Tests parse every `go-public` invocation in the skill files and in the fix plan's
  next commands against the Typer app (subcommand, flags, argument count), and run the
  wrapper against a fake `PATH`.

## Consequences

- The skill cannot be checked by running a model in CI. The dry run against the demo
  fixture and the official validator are manual, pre-release checks.
- Changing a flag name breaks the docs test, which is the point.
- The wrapper starts uvx twice per call when `go-public` is not on `PATH`; uv's cache
  keeps the second start cheap.
