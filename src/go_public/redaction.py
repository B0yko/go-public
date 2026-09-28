"""Secret masking (architecture.md "Finding model": `preview`; product spec item 11:
"Secret values are never written in full"). Shared by `scan.py` now and by
`report/*`, `show`, `redact` in later stages.
"""

from __future__ import annotations

from collections.abc import Sequence

from go_public.detect.base import Detection
from go_public.model import sha256_hex

_PREFIX_LEN = 4


def redact_secret(value: str) -> str:
    """`first 4 chars + "…" + "[len=N sha256:xxxxxxxx]"` (architecture.md)."""
    prefix = value[:_PREFIX_LEN]
    digest = sha256_hex(value)[:8]
    return f"{prefix}…[len={len(value)} sha256:{digest}]"


def make_preview(value: str, *, secret: bool, show_secrets: bool) -> str:
    """The report-safe preview for one finding's matched text.

    Only secret findings are masked; `--show-secrets` (off by default) prints the
    full value instead. Non-secret categories (stage 3+) show their matched text
    as-is: the report already handles case-by-case redaction there.
    """
    if secret and not show_secrets:
        return redact_secret(value)
    return value


def mask_secret_spans(text: str, detections: Sequence[Detection]) -> str:
    """`text` with every detection's `[start, end)` span replaced by
    `redact_secret(value)` (product spec item 20: `go-public show` "masks every
    secret span with the report's redaction"). Spans are processed in position order
    and the output is rebuilt piece by piece, so a mask that is longer than the
    secret it replaces never shifts a later span's offset; an overlapping span (only
    possible with a hostile/contradictory detector set) keeps the first and drops the
    rest rather than double-masking the same text.
    """
    ordered = sorted(detections, key=lambda d: d.start)
    pieces: list[str] = []
    cursor = 0
    for detection in ordered:
        if detection.start < cursor:
            continue
        pieces.append(text[cursor : detection.start])
        pieces.append(redact_secret(detection.value))
        cursor = detection.end
    pieces.append(text[cursor:])
    return "".join(pieces)
