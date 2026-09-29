# 2. RE2 for every rule pattern; gitleaks's own matching semantics ported, not its code

## Context

The bundled secret rule set is gitleaks's own default config (`config/gitleaks.toml`
at tag `v8.30.1`), vendored byte-for-byte because its 222 rules are the product's
main source of detections and re-deriving them by hand would drift from upstream.
Reusing the *rules* commits go-public to reusing gitleaks's *matching semantics* too:
keyword prefiltering, `secretGroup` extraction, entropy gating, and — the part with
the most behavioural surface — allowlist evaluation (`condition`, `regexTarget`,
`stopwords`, per-rule vs. global, `paths`/`commits` vs. `regexes`). A go-public rule
engine that used the same patterns but different matching rules would silently
mis-detect on some fraction of them.

gitleaks is Go, so nothing here can call its code directly. Two choices follow: which
regex engine compiles those 270 patterns (221 rule regexes + 49 allowlist regexes),
and how faithfully to port the surrounding Python logic.

## Decision

**Engine: `google-re2` (the `re2` PyPI package), not Python's `re`.** Checked on
2026-09-24 with Python 3.12 against the pinned `gitleaks.toml`
(`research/re2check.py`): counting every rule regex plus every allowlist `regexes`
entry (not `paths`, which are also regexes but not tallied by this check) gives 270
patterns. RE2 compiles all 270. Python's `re` fails on 27, of which 25 are rule
regexes — mostly inline flags that are not at the start of the pattern (Python 3.11+
rejects a bare `(?i)` placed mid-pattern; RE2 and Go's own engine treat it as scoped
from that point on) and `\z`, which Python's `re` does not support at all. Using `re`
would mean silently dropping a ninth of the rule set. RE2 also matches gitleaks's own
guarantee: linear-time matching, so no blob (including one crafted to be slow) can
trigger catastrophic backtracking — a property Python's backtracking `re` engine does
not have. The trade-off is no lookaround and no backreferences, which the gitleaks
tag's own patterns don't need either (they compile under RE2 with zero failures), and
a native-extension dependency: wheels exist for cp312 on macOS 13/14/15 (arm64 and
x86_64), manylinux (aarch64 and x86_64), and Windows (win32/amd64/arm64) as of
`google-re2` 1.1.20251105, covering every CI and release target this project has.
Python's `re` is still used, sparingly, for go-public's own non-rule string handling
where RE2's restrictions would be actively unhelpful (e.g. `pathspec`'s glob engine
internally); no rule, allowlist, or path pattern compiles with anything but `re2` —
`tests/unit/test_static_guards.py::test_rule_pattern_modules_do_not_import_python_re`
holds this.

**Semantics: ported by hand into `detect/gitleaks_config.py` and `detect/secrets.py`,
citing the source at the pinned tag, not vendored as code.** The source files read
for this port (all at
`https://github.com/gitleaks/gitleaks/blob/v8.30.1/...`):
`config/config.go` (`ViperConfig.Translate`, `extend`/`extendDefault`/`extendPath`),
`config/rule.go` (`Rule.Validate`), `config/allowlist.go` (`Allowlist.Validate`,
`CommitAllowed`/`PathAllowed`/`RegexAllowed`/`ContainsStopWord`), `config/utils.go`
(`joinRegexOr`), `detect/detect.go` (`DetectContext`, `detectRule`,
`checkCommitOrPathAllowed`, `checkFindingAllowed`, `processRequiredRules`,
`withinProximity`, `AddFinding`'s fingerprint shape), and `detect/utils.go`
(`shannonEntropy`, the generic-vs-specific overlap `filter`). Config loading is
intentionally *stricter* than gitleaks: viper's `Unmarshal` silently ignores a key
that doesn't match a known struct field, while go-public's loader treats any
unrecognised key, at any level (top-level, `[extend]`, a rule, an allowlist, a
`required` entry), as a `ConfigError` (exit 2). This catches a typo'd
`--gitleaks-config` instead of quietly running fewer checks than the user intended. A pattern that fails
to compile is the one place go-public is *more* lenient at load time: it is recorded
in `compile_failures` (that rule or allowlist entry then matches nothing) rather than
aborting the whole config, so `go-public rules check` can name every failure in one
run; a structurally empty rule (`regex` and `path` both absent) is still a hard
`ConfigError`.

Deliberately **not** ported (documented, not silently dropped):
- Base64/hex/percent decoding passes (gitleaks's `detect/codec`, up to depth 5 by
  default). go-public does not decode at all — a secret only reachable by decoding a
  blob is a documented blind spot, not a false negative in the ordinary sense.
- `gitleaks:allow` inline comments. Suppression is go-public's own
  `go-public:allow <reason>`, handled later in `suppress.py`, not in the engine.
- SARIF/CLI report plumbing, colourised printing, and SCM link generation — none of
  that is part of the matching semantics.

## Consequences

- Every rule, allowlist, and go-public's own pattern-based
  detectors compile through the same `re2` engine; a future detector reaching for
  Python's `re` for anything rule-shaped is a bug, not a style choice.
- The port is a moving target only in the sense that gitleaks itself moves; pinning
  the tag (`v8.30.1`) and citing exact file names means a future re-vendor (bumping
  the tag) has a checklist to diff against, in this file and in
  `third_party/gitleaks/NOTICE.md`.
- `minVersion` in a user's own config is honoured as a warning (config requires a
  gitleaks newer than the pinned `v8.30.1`), never an error — go-public isn't
  gitleaks, so "newer than what this port targets" is informational, not fatal.
- Two behaviours are easy to miss when testing by hand and are covered by dedicated
  unit tests instead: the generic-vs-specific overlap filter (a `generic-entropy` or
  `generic-api-key` finding is dropped when a vendor rule covers the same secret on
  the same line) and `required` multi-part rules (a rule can depend on a second,
  often `skipReport`-only, rule matching within `withinLines`/`withinColumns`).
