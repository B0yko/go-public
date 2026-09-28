# Triage reference

How to judge each finding category and rule id, what each fix action means, and how the
four plan groups map to what the user has to do. Everything here works from go-public
output; none of it needs the value of a secret.

Severity is a starting point, not a verdict. A `high` finding in a test fixture can be a
false positive; an `info` finding can still matter to the user. Ask when unsure.

## Plan groups

| Group | Meaning | What the user does |
|---|---|---|
| A. Rotate now | Every secret that ever existed anywhere in history, open or rotated | Rotate or revoke it at the provider, then record it with `go-public allow <secret-id> --rotated --reason "<text>"`; or allowlist a false positive with `go-public allow <fingerprint> --reason "<text>"` |
| B. Fix at HEAD | Present in the export ref's current files, grouped per file | Fix the file (edit, rename, strip, exclude), commit, re-scan |
| C. Removed by a squash export | Found only in history, commit or tag messages, identities, trailers, other refs or unreachable objects | Nothing, with a squash export. The export never carries it forward |
| D. Decide | Licence history, large files at HEAD, names if history were kept | The user decides; licence findings are facts to review, not legal advice |

A secret appears in group A and also in B (if it is in a current file) or C (if only in
history). A rotation record is not a fix: it never hides the finding in group B and never
stops the export from removing the value. `export --check` exits 0 only when nothing the
export cannot resolve by itself remains at or above the threshold.

## Fix actions

| Action | Meaning |
|---|---|
| `rotate` | The secret is exposed. Rotate or revoke it, then record it as rotated. Also remove it from current files (`go-public redact`) |
| `edit-line` | Change the line the report points at. Also used for tracked changes and comments inside Office documents, which strip reports but never removes |
| `delete-file` | Remove the file from the repository |
| `strip` | Run `go-public strip <file>`: removes image, PDF and Office metadata without re-encoding. The export also strips in memory by default |
| `exclude` | The file should not ship. The export drops sensitive files and internal notes by itself (auto-exclude), or list it under `[export] exclude` |
| `rename-path` | The path itself carries a deny term or a name. Rename it, then commit |
| `removed-by-squash` | Group C: the squash export drops it. No action |
| `review-licence` | Group D: read the licence transition or notice and decide. Not legal advice |
| `decide-large-file` | Group D: keep, exclude or replace the blob |
| `rewrite-identity` | Only relevant if history were kept: map the identity to the public one |
| `none` | Informational |

## Secrets (category `secret`, critical or high)

- Vendor rules (for example an AWS access key, a GitHub or Slack token, a Stripe key, a
  private key block): critical. Treat as real unless the user can show it is a documented
  example value. Always in group A.
- `generic-api-key` and `generic-entropy`: high. High-entropy value assigned to a name such
  as `key`, `token` or `secret`. Frequent false positives: hashes, UUIDs, checksums,
  lockfile integrity strings, test fixtures with random-looking data, example values in
  docs. Ask the user what the value is used for before allowlisting.
- `pkcs12-file`, private-key blocks and `.env` files are secrets even when the file looks
  like a test asset; ask where the file came from.
- A secret found only in history is still exposed to anyone who ever cloned the repository.
  Rotation is required; the squash export only removes it from what is published.
- Allowlisting: `go-public allow <fingerprint> --reason "<text>"` for one finding, a path
  glob under `[allowlist] paths` for a whole fixture directory, or an inline comment
  `go-public:allow <reason>` on the line. A reason is mandatory. Never allowlist to make a
  number go down.

## Personal data (category `pii`)

- `pii-email` (high): addresses on real domains. Reserved example domains (`example.com`,
  `.example`, `.test`, `.invalid`) are not reported. Ask whether the person agreed to be
  public; usually replace with a role or noreply address.
- `pii-phone` (high): numbers parsed in the configured regions (`[pii] phone_regions`).
  False positives: version strings, ids, timestamps that happen to parse. Fictional
  ranges reserved for films and documentation are still worth a look.
- `pii-name` (high): only with `--detect-names`; a name from history found in content.
  Common words that are also names are the usual false positive.

## Organisation identifiers (category `org-identifier`, high)

Rules `deny-term`, `deny-domain`, `deny-regex`, `deny-ticket`. They come from the user's
own deny-list, so a hit is real by definition unless the term is also an ordinary word.
Fix the file (edit-line or rename-path). If the term is legitimately public, remove it
from the deny-list rather than allowlisting each hit. The deny-list itself is private:
never quote it in commits, issues or pull requests.

## Local paths and network identifiers (medium)

- `user-path`, `macos-temp-path` (category `local-path`): a home directory or temp path of
  a real machine leaks a username and layout. Replace with a placeholder or a relative
  path. Documentation that shows a generic example path is a false positive.
- `private-ip`, `internal-host` (category `network`): private ranges and internal-suffix
  hosts (`.internal`, `.local`, `.corp`, ...). Fine in documentation about RFC-reserved
  ranges; otherwise replace with a documentation address or a placeholder host.
- `private-submodule-url`: a `.gitmodules` URL that points to a private host. Change it or
  drop the submodule; gitlinks are never exported.

## Binary metadata (category `binary-metadata`)

Rule ids `exif-gps` (high), `exif-person`, `exif-org`, `png-text`, `pdf-info`, `pdf-xmp`,
`ooxml-core`, `ooxml-app`, `ooxml-custom` and the comment and revision author rules
(medium), `exif-software`, `png-time` (low). Run `go-public strip <file>` (lossless; JPEG
orientation is kept). Tracked changes and comments in Office files are reported, never
removed automatically: the user edits the document. Archives are not scanned
(`archive-not-scanned`, info): ask what is inside. Text inside images is a known blind
spot; ask the user to look at screenshots themselves.

## Files (categories `sensitive-file`, `internal-notes`, `large-file`)

- `sensitive-file`: private keys and `.env` files are critical, other matches (dumps,
  keystores, databases) high. Exclude them; if they held real credentials, rotate.
- `internal-notes` (medium): `NOTES*.md`, `notes/`, `scratch/`, `drafts/`, `*.draft.md`,
  `internal/` and similar (`[files] internal_notes`). Usually exclude; the user may keep one if it is genuinely public-facing.
- `large-file-warn` (low, from 5 MB), `large-file-high` (medium, from 50 MB),
  `large-file-github-limit` (high, from 100 MB, which GitHub rejects). Group D at HEAD:
  the user decides to keep, exclude or move it (for example to a release asset).
- `lfs-pointer` (info): the content lives in LFS and is not scanned.
- `gitlink` (info): a submodule reference; never exported.

## Licence (category `licence`, group D)

`licence-transition` (medium), `licence-proprietary` (high; a proprietary or confidential
notice), `licence-foreign-holder` (a copyright holder other than the configured
`[licence] owner`), `licence-missing-at-head` (info). Present them as facts: what changed, at which commit, who is named. The user (or
their lawyer) decides. Do not say a licence is valid, compatible or safe.

## Identities, trailers, timezones (history)

- `identity` (medium): author, committer or tagger not in `[identity] allow`. A squash
  export replaces all of them with the export identity, so this is group C.
- `trailer` (medium with a name or email, low for ids such as Change-Id): `Signed-off-by`,
  `Co-authored-by` and similar. Group C with a squash export.
- `timezone-offset` (info): commit offsets reveal a region. Not evaluated for the exit
  code; the export commit is in UTC.
- `tracked-config-deny` (critical): a committed `.go-public.toml` with a non-empty
  `[deny]` table would publish the deny-list. Remove the deny entries from the tracked
  file; the export drops the file regardless. Keep the real deny-list in the private
  config outside the repository.

## Common false-positive patterns

- Documentation and tests that show example credentials, phone numbers or paths. Prefer
  changing the text to an obviously fake value over allowlisting.
- Hashes, digests, UUIDs, build ids, base64 test vectors flagged as `generic-entropy`.
- Vendored third-party code or lockfiles: allowlist the directory with a path glob and a
  reason, after checking the vendor's code is meant to be public.
- Reserved example domains and addresses in RFC documentation ranges.

## Reminders for the user

- Removing a secret from what you publish does not replace rotating it.
- The scan covers this clone's commits; issues, pull request refs, wikis and Actions logs
  are not scanned, which is why the export goes to a new repository.
- Text inside images and encrypted or nested archives is not inspected.
