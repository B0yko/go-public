# Real-world noise

- Date (UTC): 2026-09-29T02:01:42Z
- Hardware: Mac Studio M4 Max, 128 GB
- git: 2.50.1
- go-public: 0.1.0
- Detector commit: a07fcb42037e028c60e5d29a520d80d09325a92d
- Command: `go-public bench --real-world-dir <dir> --labels bench/labels/real-world.jsonl`

Two public repositories, each a full-history clone of one release tag, scanned with `--include-unreachable` and the default configuration. The results hold counts, rule ids, tags, SHAs and sizes only; no matched value from either repository is written anywhere in this repository.

## Repositories

| Repository | Tag | Tag commit | Clone size | Licence | Commits | Unique blobs | Blob content | Scan |
|---|---|---|---|---|---|---|---|---|
| psf/requests | v2.34.2 | `6e83187b8feb` | 14.7 MB | Apache-2.0 | 6,466 | 7,700 | 112 MB | 28.8 s |
| pallets/flask | 3.1.3 | `22d924701a6a` | 12.7 MB | BSD-3-Clause | 5,463 | 9,021 | 159 MB | 16.9 s |

## Findings per 1,000 unique blobs

Identity findings are left out (in a public repository they are true findings by definition); their count is shown in the last column.

| Repository | Critical | High | Medium | Low | Info | All | Identity |
|---|---|---|---|---|---|---|---|
| psf/requests | 17 (2.21) | 6324 (821.30) | 7601 (987.14) | 54 (7.01) | 12173 (1580.91) | 26169 (3398.57) | 836 |
| pallets/flask | 1 (0.11) | 696 (77.15) | 1023 (113.40) | 23 (2.55) | 10320 (1144.00) | 12063 (1337.21) | 905 |

Cells are count (per 1,000 unique blobs).

### psf/requests: findings by rule (identity excluded)

| Rule | Findings |
|---|---|
| timezone-offset | 12173 |
| private-ip | 7432 |
| pii-email | 6284 |
| trailer | 179 |
| generic-api-key | 24 |
| pdf-info | 16 |
| png-text | 13 |
| pii-phone | 12 |
| sensitive-file | 10 |
| pdf-xmp | 9 |
| private-key | 8 |
| generic-entropy | 3 |
| licence-transition | 3 |
| user-path | 2 |
| internal-host | 1 |

### pallets/flask: findings by rule (identity excluded)

| Rule | Findings |
|---|---|
| timezone-offset | 10318 |
| internal-host | 557 |
| pii-email | 481 |
| generic-api-key | 209 |
| user-path | 179 |
| trailer | 170 |
| private-ip | 100 |
| licence-transition | 17 |
| png-text | 15 |
| sensitive-file | 7 |
| pdf-info | 4 |
| png-time | 4 |
| archive-not-scanned | 1 |
| gitlink | 1 |

## Tuning on these repositories

The first scans of these two repositories exposed false-positive patterns that the synthetic hard negatives did not contain (numeric data such as SVG path data and coefficient tables read as phone numbers, dotted code references read as internal hosts, placeholder home directories, URL credentials read as emails, `module.Attribute` values read as credentials, and permissive licence headers read as proprietary notices). They were fixed before the detector freeze, each with a test built from runtime-assembled strings. The numbers on this page are after those fixes, so on these two repositories they are a measure of what remains, not an independent test of the patterns that were fixed.

## Precision on a reviewed sample

Up to 50 findings at critical or high, drawn with the fixed seed 20260929: strata are repository and severity, each stratum gets its proportional share (at least one draw), and findings are ordered by fingerprint before drawing. The sample is reproduced by re-running the command above on the same clones; it is labelled by the author (the labels file holds fingerprints, rule ids, verdicts and one-line reasons, never a matched value). A finding is a true positive when the flagged value is what the rule claims, whether or not publishing it is harmful; a path rule (`sensitive-file`) is judged by its name pattern only. Shares are proportional to each stratum's size, so the most common rule dominates the sample; the per-rule counts above show what the sample does not cover.

| Repository | Severity | Findings at or above high | Drawn |
|---|---|---|---|
| pallets/flask | critical | 1 | 1 |
| pallets/flask | high | 696 | 4 |
| psf/requests | critical | 17 | 1 |
| psf/requests | high | 6324 | 44 |

Overall: 50 true positives, 0 false positives among 50 labelled findings; precision 1.000.

| Slice | Labelled | TP | FP | Precision |
|---|---|---|---|---|
| repository pallets/flask | 5 | 5 | 0 | 1.000 |
| repository psf/requests | 45 | 45 | 0 | 1.000 |
| severity critical | 2 | 2 | 0 | 1.000 |
| severity high | 48 | 48 | 0 | 1.000 |
| rule generic-api-key | 1 | 1 | 0 | 1.000 |
| rule pii-email | 47 | 47 | 0 | 1.000 |
| rule sensitive-file | 2 | 2 | 0 | 1.000 |
