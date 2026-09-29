# Blind spots: measured recall

- Date (UTC): 2026-09-29T01:38:29Z
- Hardware: Mac Studio M4 Max, 128 GB
- git: 2.50.1
- go-public: 0.1.0
- Detector commit: unknown
- Size: small; seeds: 0, 1
- Command: `go-public bench --seeds 0,1 --size small --blind-spots`

Plants a static, offline scanner is not expected to catch, built without the main plant set. A plant counts as detected when a finding of the expected category sits on its blob.

| Blind spot | Plants | Detected | Recall | Detected by |
|---|---|---|---|---|
| split-secret | 2 | 0 | 0.000 | - |
| base64-secret | 2 | 0 | 0.000 | - |
| zipped-secret | 2 | 0 | 0.000 | - |
| minified-generic | 2 | 1 | 0.500 | generic-api-key |
| image-text | 2 | 0 | 0.000 | - |
| spaced-deny-term | 2 | 0 | 0.000 | - |
| xmp-gps | 2 | 0 | 0.000 | - |

Overall: 1 of 14 detected (recall 0.071).
