# Secrets baseline: go-public against gitleaks

- Date (UTC): 2026-09-29T02:07:22Z
- Hardware: Mac Studio M4 Max, 128 GB
- git: 2.50.1
- go-public: 0.1.0
- Detector commit: a07fcb42037e028c60e5d29a520d80d09325a92d
- Size: small; seeds: 2, 3, 4, 5, 6
- Command: `go-public bench --seeds 2-6 --size small --gitleaks <gitleaks-binary>`
- gitleaks: 8.30.1 (official darwin_arm64 release, default config)

Secret plants only (vendor-format and generic), on the same fixtures for both tools. The unit is an expected secret finding from the truth file. go-public's secret rules are derived from gitleaks's, so the differences below come from coverage (locations, decoding, archives, generic detection), not from the patterns.

## Commands

- gitleaks git: `gitleaks git --log-opts=--all --no-banner --log-level error --exit-code 0 --report-format json --report-path <report> <target>`
- gitleaks git replace refs ignored: `GIT_NO_REPLACE_OBJECTS=1 gitleaks git --log-opts=--all --no-banner --log-level error --exit-code 0 --report-format json --report-path <report> <target>`
- gitleaks dir: `gitleaks dir --no-banner --log-level error --exit-code 0 --report-format json --report-path <report> <target>`
- gitleaks dir archives: `gitleaks dir --no-banner --log-level error --exit-code 0 --report-format json --report-path <report> --max-archive-depth 2 <target>`
- go public: `go-public scan <fixture> --include-unreachable --config <fixture-config>`

An expected finding is *outside gitleaks's scope* when its README does not claim to cover that kind of place: it scans `git log -p` patches and directories or files. Those are not counted as misses in the in-scope recall. Reasons, with the number of expected findings of each kind in this run:

- `commit_message`: commit messages are not part of the patches it scans (10)
- `tag_message`: tag messages are not part of the patches it scans (10)
- `unreachable_blob`: objects no ref reaches are not in `git log` (10)

`gitleaks dir` sees a checkout only, so its scope is the expected findings that are in the tree at `HEAD`.

## Recall by location type

go-public is shown against all expected findings of a row; gitleaks git against the in-scope ones; gitleaks dir against those in the checkout.

| Location | Expected | Outside scope | In checkout | go-public | gitleaks git (all refs) | gitleaks git (replace refs ignored) | gitleaks dir (checkout of HEAD) |
|---|---|---|---|---|---|---|---|
| head | 15 | 0 | 15 | 15/15 | 15/15 | 15/15 | 15/15 |
| history_only | 10 | 0 | 0 | 10/10 | 0/10 | 10/10 | 0/0 |
| side_branch | 10 | 0 | 0 | 10/10 | 10/10 | 10/10 | 0/0 |
| tag_only | 10 | 0 | 0 | 10/10 | 10/10 | 10/10 | 0/0 |
| notes | 10 | 0 | 0 | 10/10 | 10/10 | 10/10 | 0/0 |
| stash | 10 | 0 | 0 | 10/10 | 10/10 | 10/10 | 0/0 |
| remote_tracking | 10 | 0 | 0 | 10/10 | 10/10 | 10/10 | 0/0 |
| replace | 10 | 0 | 0 | 10/10 | 10/10 | 10/10 | 0/0 |
| original | 5 | 0 | 0 | 5/5 | 5/5 | 5/5 | 0/0 |
| path_name | 10 | 0 | 10 | 10/10 | 10/10 | 10/10 | 10/10 |
| commit_message | 10 | 10 | 0 | 10/10 | 0/0 | 0/0 | 0/0 |
| tag_message | 10 | 10 | 0 | 10/10 | 0/0 | 0/0 | 0/0 |
| unreachable | 10 | 10 | 0 | 10/10 | 0/0 | 0/0 | 0/0 |

## Recall

| Tool | Found | Recall, all expected | In gitleaks git's scope | In the checkout (at HEAD) |
|---|---|---|---|---|
| go-public (full scan) | 130/130 | 1.000 | 100/100 (1.000) | 25/25 (1.000) |
| gitleaks git (all refs) | 90/130 | 0.692 | 90/100 (0.900) | 25/25 (1.000) |
| gitleaks git (replace refs ignored) | 100/130 | 0.769 | 100/100 (1.000) | 25/25 (1.000) |
| gitleaks dir (checkout of HEAD) | 25/130 | 0.192 | 25/100 (0.250) | 25/25 (1.000) |

By class:

| Tool | secret-generic | secret-vendor |
|---|---|---|
| go-public | 20/20 | 110/110 |
| gitleaks git (all refs) | 15/20 | 75/110 |
| gitleaks git (replace refs ignored) | 20/20 | 80/110 |
| gitleaks dir (checkout of HEAD) | 5/20 | 20/110 |

`gitleaks git` reads history through `git log -p`, which follows `refs/replace/*`. The fixtures carry replace refs, so history they cover is invisible to the plain run (10 in-scope expected findings here) and reappears when git is told to ignore them. That is how the tool behaves on such a repository; a repository without replace refs would not show this gap.

## Wall time

| Tool | Total over fixtures, s | Median per fixture, s |
|---|---|---|
| go-public scan (CLI, default jobs) | 9.22 | 1.85 |
| gitleaks git (all refs) | 1.34 | 0.27 |
| gitleaks git (replace refs ignored) | 1.33 | 0.27 |
| gitleaks dir (checkout of HEAD) | 1.12 | 0.22 |

Median of 3 runs per fixture; go-public's time includes interpreter start-up and report writing, which dominate on fixtures this small.

## Where the tools differ

Expected findings found by gitleaks git but not by go-public: none.

Expected findings found by go-public but not by gitleaks git: secret-generic:history_only:blob (5), secret-vendor:commit_message:commit_message (10), secret-vendor:history_only:blob (5), secret-vendor:tag_message:tag_message (10), secret-vendor:unreachable:unreachable_blob (10).

The same, against gitleaks git with replace refs ignored (what remains is coverage, not the replace-ref effect): secret-vendor:commit_message:commit_message (10), secret-vendor:tag_message:tag_message (10), secret-vendor:unreachable:unreachable_blob (10).

## Blind-spot secrets

The four blind-spot plants that hold a secret (built without the main plant set), matched on their blob. gitleaks decodes base64, hex and percent-encoding by default (`--max-decode-depth`) and can open archives with `--max-archive-depth`, which go-public does not do.

| Blind spot | Plants | go-public | gitleaks git | gitleaks dir | gitleaks dir, --max-archive-depth 2 |
|---|---|---|---|---|---|
| split-secret | 5 | 0/5 | 0/5 | 0/5 | 0/5 |
| base64-secret | 5 | 0/5 | 5/5 | 5/5 | 5/5 |
| zipped-secret | 5 | 0/5 | 0/5 | 0/5 | 5/5 |
| minified-generic | 5 | 5/5 | 5/5 | 5/5 | 5/5 |
