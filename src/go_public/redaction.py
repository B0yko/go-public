"""Secret masking (`preview`): secret values are never written in full. Shared by
`scan.py`, `report/*`, `show` and `redact`.
"""

from __future__ import annotations

from collections.abc import Sequence

from go_public.detect.base import Detection
from go_public.model import sha256_hex

_PREFIX_LEN = 4


def redact_secret(value: str) -> str:
    """`first 4 chars + "…" + "[len=N sha256:xxxxxxxx]"`."""
    prefix = value[:_PREFIX_LEN]
    digest = sha256_hex(value)[:8]
    return f"{prefix}…[len={len(value)} sha256:{digest}]"


def make_preview(value: str, *, secret: bool, show_secrets: bool) -> str:
    """The report-safe preview for one finding's matched text.

    Only secret findings are masked; `--show-secrets` (off by default) prints the
    full value instead. Non-secret categories show their matched text
    as-is: the report already handles case-by-case redaction there.
    """
    if secret and not show_secrets:
        return redact_secret(value)
    return value


def mask_secret_spans(text: str, detections: Sequence[Detection]) -> str:
    """`text` with every detection's `[start, end)` span replaced by
    `redact_secret(value)` (`go-public show` masks every secret span with the
    report's redaction). Overlapping spans (two rules matching
    the same or adjacent text) are merged first, so no part of either secret survives;
    the output is rebuilt piece by piece, so a mask longer than the secret it replaces
    never shifts a later span's offset.
    """
    merged: list[tuple[int, int, str]] = []  # (start, end, masked value)
    for detection in sorted(detections, key=lambda d: (d.start, -d.end)):
        if merged and detection.start < merged[-1][1]:
            start, end, value = merged[-1]
            if detection.end > end:
                merged[-1] = (start, detection.end, text[start : detection.end])
            else:
                merged[-1] = (start, end, value)
            continue
        merged.append((detection.start, detection.end, detection.value))
    pieces: list[str] = []
    cursor = 0
    for start, end, value in merged:
        pieces.append(text[cursor:start])
        pieces.append(redact_secret(value))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)
