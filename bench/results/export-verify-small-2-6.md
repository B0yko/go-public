# Export verification

- Date (UTC): 2026-09-29T02:08:29Z
- Hardware: Mac Studio M4 Max, 128 GB
- git: 2.50.1
- go-public: 0.1.0
- Detector commit: a07fcb42037e028c60e5d29a520d80d09325a92d
- Size: small; seeds: 2, 3, 4, 5, 6
- Command: `go-public bench --seeds 2-6 --size small --export-verify`

Per seed: scan, scripted fix at HEAD (a final commit that removes every HEAD plant the export cannot resolve by itself), export, re-scan at `--fail-on low`, and a fingerprint of the source before and after.

## squash

| Seed | History-only eliminated | HEAD auto-resolved eliminated | Residual true | Residual false positives | Left by design | Source unchanged | Export |
|---|---|---|---|---|---|---|---|
| 2 | 103/103 | 16/16 | 0 | 0 | - | yes | clean |
| 3 | 103/103 | 16/16 | 0 | 0 | - | yes | clean |
| 4 | 103/103 | 16/16 | 0 | 0 | - | yes | clean |
| 5 | 103/103 | 16/16 | 0 | 0 | - | yes | clean |
| 6 | 103/103 | 16/16 | 0 | 0 | - | yes | clean |
| all | 515/515 | 80/80 | 0 | 0 | - | yes | pass |

## keep-history

| Seed | History-only eliminated | HEAD auto-resolved eliminated | Residual true | Residual false positives | Left by design | Source unchanged | Export |
|---|---|---|---|---|---|---|---|
| 2 | 94/94 | 16/16 | 0 | 0 | 9 | yes | clean |
| 3 | 94/94 | 16/16 | 0 | 0 | 9 | yes | clean |
| 4 | 94/94 | 16/16 | 0 | 0 | 9 | yes | clean |
| 5 | 94/94 | 16/16 | 0 | 0 | 9 | yes | clean |
| 6 | 94/94 | 16/16 | 0 | 0 | 9 | yes | clean |
| all | 470/470 | 80/80 | 0 | 0 | 45 | yes | pass |

Left by design: licence history (kept as it was, needs a decision), blobs under the size limit that is dropped, LFS pointers, and OOXML comment and revision authors (`strip` reports them and never removes them; exclude the file to drop it from history). They are listed in the re-scan report and not scored. This run: LFS pointer: 5, OOXML comments and revisions: 10, large file below the size limit: 5, licence history: 25.
