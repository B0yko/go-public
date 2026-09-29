# Recall by location type: full scan against `--head-only`

- Date (UTC): 2026-09-29T02:05:27Z
- Hardware: Mac Studio M4 Max, 128 GB
- git: 2.50.1
- go-public: 0.1.0
- Detector commit: a07fcb42037e028c60e5d29a520d80d09325a92d
- Size: small; seeds: 2, 3, 4, 5, 6
- Command: `go-public bench --seeds 2-6 --size small --compare-head-only`

`--head-only` scans only the export ref's tree, as a working-tree scanner would. Counts are expected findings from the truth files; a finding counts as found by `--head-only` only when the planted issue itself is at the export ref.

| Location | Expected | Full found | Full recall | Head-only found | Head-only recall |
|---|---|---|---|---|---|
| head | 140 | 140 | 1.000 | 140 | 1.000 |
| binary fields | 50 | 50 | 1.000 | 50 | 1.000 |
| history-only | 50 | 50 | 1.000 | 0 | 0.000 |
| side branch | 55 | 55 | 1.000 | 0 | 0.000 |
| tag | 45 | 45 | 1.000 | 0 | 0.000 |
| notes/stash/remote/replace/original | 130 | 130 | 1.000 | 0 | 0.000 |
| messages | 50 | 50 | 1.000 | 0 | 0.000 |
| identities | 15 | 15 | 1.000 | 0 | 0.000 |
| ref names | 5 | 5 | 1.000 | 0 | 0.000 |
| licence transitions | 25 | 25 | 1.000 | 10 | 0.400 |
| unreachable | 30 | 30 | 1.000 | 0 | 0.000 |
| all locations | 595 | 595 | 1.000 | 200 | 0.336 |
