# go-public runtime

- Date (UTC): 2026-09-29T02:00:33Z
- Hardware: Mac Studio M4 Max, 128 GB
- git: 2.50.1
- go-public: 0.1.0
- Detector commit: a07fcb42037e028c60e5d29a520d80d09325a92d
- Size: medium; seeds: 100
- Command: `go-public bench --seeds 100 --size medium --runtime --repeat 3`

Median of 3 runs of the full command line under `/usr/bin/time -l`. Peak RSS is the largest single process (parent or one worker), not the sum over workers. Load average is the 1-minute figure at the start of each run; the machine is shared with other jobs. The default `--jobs` is the CPU count (16 here).

## Synthetic medium fixture, seed 100

3,017 commits, 4 branches, 30 tags (6 annotated), 12,049 unique blobs, 197 MB of blob content, 0 unreachable blobs, 0 findings.

| Command | Wall s | Peak RSS MB | Blobs/s | Load avg |
|---|---|---|---|---|
| scan, default | 5.15 | 184 | 2340 | 9.9, 11.9, 11.7 |
| scan, `--jobs 1` | 34.96 | 191 | 345 | 11.3, 10.1, 9.1 |
| squash export | 17.98 | 167 |  | 8.7, 10.8, 12.7 |

Full scan with the default `--jobs`: 5.15 s, which meets the 60 s target.

## pallets/flask at 3.1.3 (real-world clone)

5,463 commits, 0 branches, 63 tags (35 annotated), 9,021 unique blobs, 159 MB of blob content, 0 unreachable blobs, 12968 findings (tag: 3.1.3, tag commit: 22d924701a6a, clone size mb: 12.7).

| Command | Wall s | Peak RSS MB | Blobs/s | Load avg |
|---|---|---|---|---|
| scan, default | 15.99 | 415 | 564 | 12.2, 14.8, 14.8 |
| scan, `--jobs 1` | 73.90 | 418 | 122 | 14.8, 11.0, 8.9 |
