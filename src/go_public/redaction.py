"""Secret masking (architecture.md "Finding model": `preview`; product spec item 11:
"Secret values are never written in full"). Shared by `scan.py` now and by
`report/*`, `show`, `redact` in later stages.
"""

from __future__ import annotations

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
