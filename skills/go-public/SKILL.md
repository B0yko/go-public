---
name: go-public
description: Audit a private git repository (every ref, commit and blob, not just the working tree) for secrets, personal data, organisation identifiers and other material before it is open-sourced, fix what is found together with the user, and produce a clean single-commit export. Use when the user wants to open-source, publish or "go public" with a repository, or asks whether a repository is safe to release.
argument-hint: "[repo-path]"
allowed-tools:
  - Bash(${CLAUDE_PLUGIN_ROOT}/scripts/go-public *)
  - Bash("${CLAUDE_PLUGIN_ROOT}/scripts/go-public" *)
  - Bash(git status *)
---

# go-public: prepare a private repository for open source

The repository to prepare is `$ARGUMENTS`. If that is empty, use the current directory and tell the user which repository you are about to audit before you run anything.

You are walking the user through eight steps. Do them in order, do not skip ahead, and stop to ask wherever a step says so. The scan is read-only: `go-public` never changes the source repository, never pushes and makes no network calls.

Every `go-public` call goes through the wrapper, written exactly like this (it picks the matching installed version or runs the plugin's own copy through `uvx`):

```
"${CLAUDE_PLUGIN_ROOT}/scripts/go-public" <subcommand> ...
```

Wrapper exit codes beyond go-public's own: 127 means `uv` is missing (show the user the install instructions the wrapper printed and stop), 126 means go-public could not be started (show the message). go-public's own codes: 0 nothing at or above the threshold, 1 findings (this is a result, not a failure), 2 usage or config error, 3 git error or unsupported repository state (shallow, partial clone and SHA-256 repositories are called out in the scan output).

When you need to judge a category, rule id or fix action, read `references/triage.md` in this skill's folder (`${CLAUDE_SKILL_DIR}/references/triage.md`).

## Rules that never bend

- Never print, `cat`, `git show`, `git diff`, `grep` or open with a file-reading tool a blob, file or line that carries a secret finding. Secret values must never enter your context. Work only from go-public output: the summary, `report.md`, `report.json`, and `go-public show`. Never pass `--show-secrets`.
- To look at a file that has a secret finding, use `go-public show`. To replace a secret, use `go-public redact`. When neither fits (binary file, several identical spans, a value that is not a plain replacement), ask the user to edit the file by hand and tell them the path and line from the report.
- Never put report contents in commits, issues, pull requests or chat messages destined for other people. The report is local and private; so is the deny-list.
- Never amend, rebase, filter or force-push the source repository, and never delete it.
- Never make the existing private repository public. Publish the export as a new repository (step 8).
- Removing a secret from what gets published does not replace rotating it. Treat every secret that ever sat in history as exposed.

## Steps

### 1. Set up the config outside the repository

Create the config template. It is written under the user's config directory, never inside the repository, and lists the identities found in history as comments:

```
"${CLAUDE_PLUGIN_ROOT}/scripts/go-public" init <repo>
```

It prints `wrote <config-file>`: keep that path, because step 7 needs it. If it reports that a config already exists, read that file and reuse it. Then ask the user, and write the answers into the config file with an edit (it is outside the repository):

- The public identity: the name and email that should be the only author of the export, `[export] author`, and the same identity in `[identity] allow`. Use a noreply or otherwise public address.
- The deny-list under `[deny]`: organisation names and abbreviations, clients, product codenames (`terms`), internal or client domains and internal hostnames (`domains`), cloud or project IDs (`regex`), ticket keys (`ticket_keys`) and people who must not appear (`names`).
- The threshold: recommend `fail_on = "medium"` under `[scan]`, so local paths, internal hosts and identities count too.

Later commands find the config automatically (`allow` needs `--repo <repo>` to know which repository's config and latest report to use). Pass `--config <path>` only if the user chose another location. Remind the user that the scan sees the commits of this clone only: to include branches that were never fetched, scan a fresh `git clone --mirror` instead.

### 2. Scan

```
"${CLAUDE_PLUGIN_ROOT}/scripts/go-public" scan <repo> --include-unreachable --summary-json
```

Exit code 1 only means there are findings. The JSON output does not carry warnings. Read the Warnings section of `reports.md` and relay each one (uncommitted changes, shallow or partial clone, missing objects, LFS pointers), because they change what the scan can see.

### 3. Summarise

From the JSON on stdout, tell the user in a few lines: the counts per group (`groups` A to D), per severity and per category, and how many findings block (`blocking`). Give them the path of the HTML report (`reports.html`) so they can open it in a browser, and mention `reports.md`. Explain the four groups in one sentence each:

- A: secrets to rotate. B: things to fix in the current files. C: found only in history, dropped by a squash export. D: decisions (licence history, large files).

### 4. Group A: secrets

Read the group A table in `reports.md`. For every secret, show the user its id, rule, redacted preview, whether it is at HEAD and where it was found (paths, commits, refs), never the value. For each one the user decides:

- It was rotated (or revoked). Record it:

  ```
  "${CLAUDE_PLUGIN_ROOT}/scripts/go-public" allow <secret-id> --rotated --repo <repo> --reason "<how and when it was rotated>"
  ```

- It is a false positive (a placeholder, a public test key, a hash). Allowlist it with a written reason:

  ```
  "${CLAUDE_PLUGIN_ROOT}/scripts/go-public" allow <fingerprint> --repo <repo> --reason "<why this is not a secret>"
  ```

  The fingerprint comes from the findings table in `reports.md` or `report.json`. Path globs and inline `go-public:allow <reason>` comments also work; see `references/triage.md`.

- It is neither yet. Say plainly that publishing is unsafe until it is rotated, and move on.

A rotation record does not remove the secret from the current files. Secrets at HEAD are also group B items and must still be removed from the files (step 5).

### 5. Group B: fix the current files, file by file

Take the group B table row by row. For each file, tell the user what was found and the action the plan proposes, and propose a concrete edit. Apply an edit only after the user approves it. The line and column of each finding are in `report.json` (`findings[].location`; `plan.B[].findings` lists a row's fingerprints). Rows whose action is `exclude` are sensitive files and internal notes that the export drops by itself: say so, and leave them unless the user wants to keep the file (then its content has to change).

- File with a secret finding (its category list contains `secret`): look at it only with `go-public show`, which masks every secret span:

  ```
  "${CLAUDE_PLUGIN_ROOT}/scripts/go-public" show <repo> <path>
  ```

  Replace a secret with `redact`, using the secret id from group A whose `paths` include this file. It edits the working-tree file only, and refuses unless the id matches exactly one span:

  ```
  "${CLAUDE_PLUGIN_ROOT}/scripts/go-public" redact <repo>/<path> --finding <secret-id> --with "<placeholder>"
  ```

  Suggest an environment variable read or a `REPLACE_ME` style placeholder that fits the file. Two ids on the same value (for example a vendor rule and `generic-api-key`) share one span: the first `redact` replaces it and the second reports that nothing matches, which is fine. A secret found by file name or type (a key store, a private key file) cannot be redacted: propose removing the file, and if `redact` refuses for any other reason, or the file needs a structural change, ask the user to edit it by hand. Do not read the file yourself.
- File without a secret finding: you may read it and edit it after approval. Actions: `edit-line` (change the line the report points at; a replacement that is itself a home path or a real-looking number is found again, so use a relative path or plain words), `rename-path` (rename the path so it carries no deny term, with `git mv`), `strip` (metadata in an image, PDF or Office file, removed losslessly; tracked changes and comments in Office files are only reported, so edit or remove the document):

  ```
  "${CLAUDE_PLUGIN_ROOT}/scripts/go-public" strip <repo>/<path>
  ```

- Groups C and D: C needs no action with a squash export (mention that names and identities in history are gone in the export). For D, present each licence or large-file finding from the findings table and let the user decide; licence findings are facts to review, not legal advice. A proprietary notice or a foreign copyright holder in a current file also blocks the export until the user edits or removes the file, or allowlists the finding with a reason.

The scan reads commits, not the working tree. Edits count only once committed, so ask the user whether you may commit them in the source repository with a normal commit (`git status --short` shows what changed; add only the files you edited, with a plain message that does not quote the report). If they prefer not to commit on the current branch, offer a new branch and pass `--ref <branch>` to `scan` and `export`. If they decline both, say that the re-scan cannot see the edits.

### 6. Re-scan

After committing, scan again and check the summary:

```
"${CLAUDE_PLUGIN_ROOT}/scripts/go-public" scan <repo> --include-unreachable --summary-json
```

Repeat step 5 until group B is empty in the JSON, or until the export pre-check passes. The pre-check ignores group B items the export resolves by itself (sensitive files, internal notes, strippable metadata) and everything found only in history; it also lists the group D items that block:

```
"${CLAUDE_PLUGIN_ROOT}/scripts/go-public" export <repo> --check
```

Exit 0 means the export can proceed; exit 1 lists what still blocks it.

### 7. Export and re-scan

Ask the user for the output directory (it must not exist or be empty, and must be outside the source repository), then export. The export is a single commit by the public identity; commit ids change and signatures are dropped. It re-scans itself with `--include-unreachable`:

```
"${CLAUDE_PLUGIN_ROOT}/scripts/go-public" export <repo> --out <export-dir>
```

Then confirm independently by scanning the export. The config is found by directory name, so pass the config file that `init` printed in step 1, or the allowlists and the public identity are not applied:

```
"${CLAUDE_PLUGIN_ROOT}/scripts/go-public" scan <export-dir> --config <config-file> --include-unreachable --summary-json
```

`NOT CLEAN` or a non-zero `blocking` count sends you back to step 5. Do not use `--force-export` to get past it.

### 8. Stop, summarise, then publish only on instruction

Stop here. Summarise for the user: what was found and fixed, which secrets are recorded as rotated and which are not, what was left open and why, and where the export is. Print the publish commands and do not run them:

```
gh repo create <name> --public --source <export-dir> --push
```

Say explicitly: this publishes the export as a new repository; the private repository stays private, because making it public would expose every ref, pull request ref, issue, wiki and Actions log, and go-public scans none of those. Also remind them to rotate the secrets from group A that are not yet rotated.

Run the publish commands only when the user explicitly tells you to in the conversation. Afterwards verify the remote holds exactly what was exported: `git ls-remote <url>` must show the export commit (compare with `git -C <export-dir> rev-parse HEAD`) on `refs/heads/main` and no other refs. Report any difference at once and do not push anything else.
