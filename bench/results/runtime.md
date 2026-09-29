# go-public runtime

- Date (UTC): 2026-09-28T21:52:32Z
- Hardware: Mac Studio M4 Max, 128 GB
- git: 2.50.1
- go-public: 0.1.0
- Detector commit: unknown
- Size: medium; seeds: 100
- Command: `go-public bench --seeds 100 --size medium --runtime --repeat 3`

Median of 3 runs of the full command line under `/usr/bin/time -l`. Peak RSS is the largest single process (parent or one worker), not the sum over workers. Load average is the 1-minute figure at the start of each run; the machine is shared with other jobs. The default `--jobs` is the CPU count (16 here).

## Synthetic medium fixture, seed 100

3,017 commits, 4 branches, 30 tags (6 annotated), 12,049 unique blobs, 197 MB of blob content, 0 unreachable blobs, 0 findings.

| Command | Wall s | Peak RSS MB | Blobs/s | Load avg |
|---|---|---|---|---|
| scan, default | 5.20 | 183 | 2317 | 12.5, 14.3, 15.1 |
| scan, `--jobs 1` | 34.84 | 191 | 346 | 15.9, 12.6, 10.9 |
| squash export | 24.43 | 167 |  | 9.9, 11.8, 11.8 |

Full scan with the default `--jobs`: 5.20 s, which meets the 60 s target.
