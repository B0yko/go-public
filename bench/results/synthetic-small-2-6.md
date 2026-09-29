# Synthetic bench: per-class recall and precision

- Date (UTC): 2026-09-29T02:04:42Z
- Hardware: Mac Studio M4 Max, 128 GB
- git: 2.50.1
- go-public: 0.1.0
- Detector commit: a07fcb42037e028c60e5d29a520d80d09325a92d
- Size: small; seeds: 2, 3, 4, 5, 6
- Command: `go-public bench --seeds 2-6 --size small`

Pooled counts over the listed seeds. A finding that matches no truth entry is a false positive in its own class; duplicates of one truth entry count once.

| Class | Plants | Expected | TP | FN | FP | Recall | Precision | Min seed recall | Min seed precision | Gate | Result |
|---|---|---|---|---|---|---|---|---|---|---|---|
| secret-vendor | 100 | 110 | 110 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| secret-generic | 20 | 20 | 20 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.85 | pass |
| pii-email | 30 | 30 | 30 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| pii-phone | 30 | 30 | 30 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.85 | pass |
| pii-name | 15 | 15 | 15 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| org-identifier | 75 | 75 | 75 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| local-path | 40 | 40 | 40 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| network | 40 | 85 | 85 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| binary-metadata | 50 | 50 | 50 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| licence | 20 | 30 | 30 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| large-file | 15 | 15 | 15 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| sensitive-file | 30 | 30 | 30 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| internal-notes | 20 | 20 | 20 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| identity | 15 | 15 | 15 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |
| trailer | 30 | 30 | 30 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | >= 0.95 | pass |

All gates pass.
