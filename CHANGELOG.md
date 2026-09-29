# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-29

First release.

### Added

- `go-public scan`: an inventory of every ref (branches, tags, remote-tracking refs, notes, stash, replace and original refs), every commit and annotated tag and every unique blob, with optional scanning of unreachable objects and a `--head-only` comparison mode. Warnings for shallow clones, partial clones with missing objects, uncommitted changes and LFS pointers.
- Secret detection with the gitleaks v8.30.1 rule set (vendored, MIT) run through a port of its matching semantics on RE2, your own gitleaks-format config through `--gitleaks-config`, and a generic detector for high-entropy values in assignments.
- Detection of personal data (emails, phone numbers, names from a list or from history), organisation identifiers from a deny-list (terms with generated variants, domains, regexes, ticket keys), local paths, private addresses and internal hostnames, binary metadata (JPEG, PNG, WebP, TIFF, PDF, OOXML), licence history, large files, sensitive files and internal notes, commit identities, trailers and timezone offsets.
- Reports in Markdown, self-contained HTML and JSON (with a committed JSON Schema), written outside the repository with restricted permissions, and a four-group fix plan (rotate now, fix at HEAD, removed by a squash export, decide).
- `go-public allow` for allowlist entries and rotation records, path-glob allowlists and inline `go-public:allow` comments.
- `go-public export`: a squash export built directly in a new object store, with binary metadata stripped in memory and a re-scan of the result, and `--keep-history`, which rewrites the branch's history with git-filter-repo. `--check` runs only the pre-check.
- `go-public strip`, `show` and `redact`, `init` and `demo`.
- `go-public fixture` and `go-public bench`: synthetic repositories with planted issues, a per-category recall and precision table, a comparison with a HEAD-only scan, a baseline against gitleaks, export verification, a noise run on two public repositories, runtime measurements and blind-spot recall. Results are committed under `bench/results/`.
- A plugin with a guided `/go-public` workflow (see the README), and a wrapper script that finds or starts the matching version.
- Continuous integration on Linux and macOS, including a self-scan of this repository, and a release workflow.

### Known limitations

See the limitations section of the README: blind spots with measured recall, no named-entity recognition, archives other than OOXML are not scanned, hosted surfaces are not scanned, SHA-256 repositories exit with code 3, and Windows is untested.

[0.1.0]: https://github.com/B0yko/go-public/releases/tag/v0.1.0
