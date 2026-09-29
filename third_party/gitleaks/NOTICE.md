# gitleaks

go-public vendors two files from [gitleaks](https://github.com/gitleaks/gitleaks) at
tag `v8.30.1` (https://github.com/gitleaks/gitleaks/tree/v8.30.1):

- `config/gitleaks.toml` → `src/go_public/rules/gitleaks.toml` (byte-for-byte), the
  default rule set (222 rules, 221 with a content regex, 1 path-only, plus the global
  allowlist).
- `LICENSE` → `src/go_public/rules/LICENSE.gitleaks` and `third_party/gitleaks/LICENSE`
  (byte-for-byte), gitleaks's MIT licence.

go-public's own `src/go_public/detect/secrets.py` and
`src/go_public/detect/gitleaks_config.py` are a from-scratch Python port of the
matching semantics in gitleaks's `detect` and `config` packages at the same tag
(keyword prefiltering, entropy, allowlist evaluation, required rules, the
generic-vs-specific overlap filter) — no gitleaks Go source or binary is redistributed
beyond the two files named above. See `docs/adr/0002-re2-and-ported-gitleaks-semantics.md`
for the cited source files and the ported-versus-not-ported behaviour.

GitHub secret scanning reports the vendored `gitleaks.toml` as holding Google API keys.
They are the 16 public keys that upstream lists in the allowlist of its `gcp-api-key`
rule, as known false positives, so a scan does not flag them. The file is kept
byte-for-byte as upstream ships it, and these alerts on this repository are closed as
false positives.

gitleaks is Copyright (c) 2019 Zachary Rice, licensed under the MIT License (see
`LICENSE` in this directory).
