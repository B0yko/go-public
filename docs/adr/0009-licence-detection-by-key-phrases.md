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

`detect_notice` (the proprietary/confidential check) runs over every blob and
message's text, not just licence-relevant paths, since stage-3.md asks for coverage
of "licence files, SPDX/header comment blocks at file top" — a notice can open any
source file. It requires the flagged word to *open* a line (after optional
whitespace and a single comment marker), not merely appear as a substring, so
`_PROPRIETARY_KEYWORDS`'s own definition and this file's docstring do not self-flag
on go-public's self-scan, and so a sentence that discusses the concept in passing
("...explains proprietary licences...") is not confused with an actual banner.

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
- The proprietary-notice regex intentionally trades some recall (a notice that never
  opens a line, e.g. buried mid-paragraph) for precision (no false hits on this very
  file's own vocabulary, or on the Data section's committed prose about the feature).
- `bench/plants/licence.py`'s own transition plants double as `detect_notice`'s test
  data: one transition's "to" text is deliberately proprietary-classified via the
  "all rights reserved, no grant phrase" path rather than the literal
  "confidential"/"proprietary" words, so it does not also trip `detect_notice` on the
  same blob and require a second expected finding for one plant.
