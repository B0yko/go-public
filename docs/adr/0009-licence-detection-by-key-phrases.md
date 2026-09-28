# 9. Identify licences by key phrase, not by a licence-classification library

## Context

Product spec item 7 asks for licence history: every commit that changes a licence
file or a manifest's `license` field, proprietary/confidential notices anywhere in
history, copyright holders that differ from the configured owner, and whether HEAD
has a licence at all. None of this is a legal opinion — the README says so — it is a
small set of facts a maintainer needs before publishing: did the licence change, does
anything in history say "Proprietary", whose name is on the copyright line.

A dedicated licence-classification library (e.g. one built on the ScanCode or SPDX
licence-list corpora) would recognise far more licence texts and their near-verbatim
variants, at the cost of a runtime dependency whose match confidence is itself
probabilistic and whose output vocabulary does not map cleanly onto "did the licence
change from A to B". go-public's own scope is the common-case licences a v0.1 needs
to report a transition, a proprietary notice or a missing licence — not to be a
licence-identification product in its own right.

## Decision

`detect/licence.py` matches lower-cased text against a short, ordered list of
canonical key phrases: MIT, Apache-2.0, BSD-2/3-Clause, ISC, MPL-2.0, GPL-2.0/3.0,
LGPL-2.1/3.0, AGPL-3.0 and Unlicense, each identified by the same handful of
sentences every real instance of that licence's text repeats verbatim (e.g. Apache-2.0
needs both "apache license" and "version 2.0"; BSD-3-Clause needs "neither the name"
in addition to BSD-2-Clause's own phrase, so the more specific tuple is tried first).
Anything not matched falls through to a proprietary heuristic — the literal words
"confidential"/"proprietary" anywhere, or "all rights reserved" with no
permission-grant phrase nearby — and finally to `unknown`. `SPDX-License-Identifier:
<id>` headers are read separately and mapped to the same canonical labels, so a
transition can compare a licence-file's prose against a manifest's SPDX id on equal
footing.

Scope is deliberately narrow: transition and missing-at-head tracking only reads
`LICENSE*`/`LICENCE*`/`COPYING*` files and the three manifests item 7 names
(`pyproject.toml`, `package.json`, `Cargo.toml`) — a small, path-identifiable set, so
`scan.py` fetches only the blobs that are actually relevant rather than every text
blob in history. A stray `SPDX-License-Identifier` header in an arbitrary source file
is still found (it feeds the proprietary/notice scan, which already reads every
blob's text as part of the normal pipeline) but does not itself register as a
transition; a source file's own SPDX header describing *that file's* licence is a
different fact from "the project's licence changed", and conflating the two would
turn every vendored file with its own SPDX header into a spurious transition.

`detect_notice` (the proprietary/confidential check) runs over blob content only,
never commit/tag message text (stage-4.md: a notice is a fact about a file in
history, not about prose in a commit message — the initial stage-3b version ran over
any text and over-reached). It requires the flagged word to *open* a line, so
`_PROPRIETARY_KEYWORDS`'s own definition and this file's docstring do not self-flag
on go-public's self-scan, and so a sentence that discusses the concept in passing
("...explains proprietary licences...") is not confused with an actual banner. Where
it is allowed to open a line depends on the path: a licence-relevant file
(`LICENSE*`/`LICENCE*`/`COPYING*`, or one of the three manifests) is read anywhere,
since the whole file *is* the licence text; anything else is read only in its header
block (the first 30 lines) and only on a comment line (`#`, `//`, `/*`, ` *`, `--`,
`<!--`, `;`) — an SPDX-style header already starts with one of these — so an ordinary
Markdown paragraph or docstring that happens to open with the word never matches. The
same "all rights reserved with no permission-grant phrase" heuristic
`identify_licence_text` uses for whole-file classification also feeds this
line-anchored check, scoped to the same text `detect_notice` actually reads (the
whole file when licence-relevant, else just the header block).

Copyright-holder extraction is a single regex (`Copyright ... <holder>`) run only
against paths `is_licence_file_path` recognises, matching product spec item 7's
narrower "copyright holders that differ from the configured owner" (a licence-file
concern, not a general document scan).

## Consequences

- Recall is bounded by the phrase list: a licence whose text does not repeat one of
  these known sentences (a heavily reworded licence, a licence this list does not
  cover) reports `unknown` rather than a wrong specific label — the same trade-off
  the generic-entropy detector already makes elsewhere in this codebase, favouring a
  visible "look at this" over a confident-sounding wrong answer.
- A repository with no `LICENSE*`/`LICENCE*`/`COPYING*` file and no recognised
  manifest `license` field legitimately reports `licence-missing-at-head` (info) —
  including `go-public fixture`'s own synthetic repositories, which is why
  `bench/fixture.py` now commits a neutral MIT `LICENSE` regardless of `--no-plants`
  (STATUS.md): the Data section's "`--no-plants` scans to zero findings" contract
  would otherwise never hold for any fixture, since no filler template names a
  licence file.
- The proprietary-notice check intentionally trades some recall (a notice that never
  opens a line, e.g. buried mid-paragraph, or one past line 30 of an unrelated file)
  for precision (no false hits on this very file's own vocabulary, on the Data
  section's committed prose about the feature, or — since stage 4 — on any commit
  message discussing the feature; before that fix, this repository's own history
  self-flagged two commit messages that merely used the word "proprietary" in prose,
  recorded as a stage-3 deviation in STATUS.md and now resolved).
- `bench/plants/licence.py`'s Apache-2.0 -> proprietary transition plant's "to" text
  is both `licence-transition`-classified and, since it sits in a `LICENSE`-relevant
  file and its "All rights reserved..." sentence opens its own line, a genuine
  `detect_notice` hit — a real co-occurrence on real content, so the plant declares
  both expected findings rather than being reworded to dodge the second one.
