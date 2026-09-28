# 10. Synthetic bench, scripted export fix, and the generic-entropy threshold

## Context

The README's numbers come from `go-public bench` on synthetic repositories that
`go-public fixture` builds from a seed. The author of the fixtures and of the detectors
is the same, so a synthetic score is an upper bound. Three design choices keep the
numbers honest and reproducible.

## Decision

- **Truth and matching.** Every fixture ships a `truth.jsonl` listing each plant with all
  the findings it must produce. A finding matches an expected entry when category and
  location key agree (blob and line, path, commit, tag, ref, identity, licence
  transition). Findings that share a category, eval class and key are scored as one, so
  duplicates and overlapping generic-secret hits on one span count once. Any other
  finding in an evaluated class is a false positive in that class.
- **Hard negatives and `--no-plants`.** Each `small` seed carries about 160 hard
  negatives (16 kinds, ten each; bare digit runs and lockfile sizes that `phonenumbers`
  would accept among them) that look like plants but must never be flagged. A
  `--no-plants` fixture keeps the filler and the negatives, uses only the public identity
  and must scan to zero findings. Tests run this for tiny seeds 0-3 and small seed 0.
- **Export verification without a commit.** `bench --export-verify` needs a "fix at HEAD"
  step. The generator builds a deterministic variant instead: one final commit on main
  deletes every HEAD-resident plant that the export cannot resolve by itself (the same
  rule the pre-check uses: sensitive files and internal notes are dropped, strippable
  metadata is stripped, everything else blocks). The plants it removes become
  history-only in that variant's truth. Export modes register in one table, so the
  history-preserving mode plugs in with the same columns.
- **Blind spots stay out of the main table.** Blind-spot plants sit in their own truth file
  (`truth.blind.jsonl`), are built without the main plant set for the blind-spot run, and
  are scored per kind by blob and category.
- **Threshold tuning.** Only seeds 0 and 1 (tiny and small) are used for tuning. The
  sweep for `[secrets] generic_entropy` showed: at 3.25 and below the detector flags
  the `YOUR_API_KEY_HERE` placeholder hard negative (entropy about 3.2); from 3.3 to 4.3 every
  planted value is found by go-public's own detector; from 4.4 up it starts to miss
  planted values (the vendored `generic-api-key` rule still finds them). The default is
  4.0, inside the plateau with a margin on the recall side.

## Consequences

- Held-out seeds (2-6, 7-11) are never used to change a threshold; they run once after
  the detector freeze.
- The scripted fix depends on the plant metadata; a new plant category must declare
  where its findings live (tree or history) for the variant to handle it.
- The 4.0 default is tuned on synthetic values (random base62 strings of length 32). Real
  credentials with lower entropy are still covered by the vendor rules and by
  `generic-api-key`; the README says the synthetic scores are an upper bound.
