# 12. Real-world noise and the gitleaks baseline

## Context

Synthetic scores are an upper bound: the fixture generator and the detectors have the
same author. Two bench modes look at the detectors from the outside, on data the author
did not write: noise on real public repositories, and a comparison with gitleaks on the
same fixtures.

## Decision

- **Real-world noise** (`bench --real-world-dir`): `psf/requests` at `v2.34.2` and
  `pallets/flask` at `3.1.3` are cloned at bench time through the clone-only runner as
  bare, single-branch clones of the tag (`--single-branch --branch <tag>`), so the
  history scanned is the history up to the release and does not grow when upstream
  moves on; the tags, and so the fingerprints in the labels file, stay valid. The bench
  records the tag object, the commit, the clone size and the licence text found at the
  tag, and refuses to run when a licence is not the expected one.
- Findings are counted per 1,000 unique blobs by severity, identity findings excluded
  (in a public repository they are true findings by definition; only their count is
  shown). A sample of up to 50 findings at high or above is drawn with a fixed seed,
  stratified by repository and severity (proportional shares, at least one draw per
  stratum, findings ordered by fingerprint before drawing). The author labels it from a
  private file next to the clones; precision is computed from the labels file
  (fingerprint, rule id, verdict, one-line reason).
- No matched value leaves the private directory. The results and the labels file are
  checked against every matched value of medium severity or above before they are
  written, and the bench refuses to write them on a hit (the message names rules, not
  values).
- Real-world scans found false-positive patterns that the synthetic hard negatives did
  not contain (numeric data read as phone numbers, code references read as internal
  hosts, placeholder users, URL credentials read as emails, `module.Attribute` read as
  a credential). They were fixed before the detector freeze, each with a test that
  builds its strings at runtime.
- **gitleaks baseline** (`bench --gitleaks`): secret plants only, by location type, with
  gitleaks's default configuration. `gitleaks git --log-opts=--all` covers all refs; a
  second run with `GIT_NO_REPLACE_OBJECTS=1` separates the effect of replace refs
  (`git log` follows them, which hides the replaced history from gitleaks) from
  detection gaps; `gitleaks dir` over a checkout of `HEAD` (made through the export
  runner, `.git` removed) stands in for a working-tree scanner. Findings are mapped
  back to truth keys by resolving `commit:file` (or `HEAD:file`) to a blob id.
- Locations the gitleaks README does not claim (commit and tag messages, unreachable
  objects, file names) are reported as outside its scope, not counted as misses.

## Consequences

- The real-world clone is not the whole upstream repository: branches and tags after
  the pinned release are not scanned.
- Precision on the real-world sample depends on one person's labels. Path rules
  (`sensitive-file`) are labelled by whether the name matches what the rule claims,
  not by whether the file's content is sensitive.
- The gitleaks comparison is on synthetic fixtures, so it shows coverage differences
  (locations, decoding, archives), not a pattern-quality difference: go-public's secret
  rules are derived from gitleaks's.
