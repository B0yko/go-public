"""`go-public show` and `go-public redact` (product spec item 20).

`show` prints a file as it is at a ref, read through the read-only source runner, with
every secret span masked by the report's redaction. `redact` replaces exactly one
secret span in a working-tree file; it never runs git, so the index and history are
untouched by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from go_public import scan as scan_mod
from go_public.detect import base
from go_public.detect.base import Detection
from go_public.errors import UsageError
from go_public.git.objects import blob_id
from go_public.git.runner import GitRunner
from go_public.model import make_fingerprint, make_group_id
from go_public.redaction import mask_secret_spans

_BLOB_MODES = frozenset({"100644", "100755", "120000"})


def _repo_relative(path: str) -> str:
    posix = PurePosixPath(path)
    parts = [p for p in posix.parts if p != "."]
    if posix.is_absolute() or ".." in parts or not parts:
        raise UsageError(f"path must be repository-relative and stay inside it: {path!r}")
    return "/".join(parts)


def _text_or_refuse(content: bytes, *, max_scan_mb: int, what: str) -> str:
    route = base.route_blob(content, max_scan_mb=max_scan_mb)
    if route.kind == "text":
        return route.text or ""
    if route.kind == "large":
        raise UsageError(f"{what} is larger than max_scan_mb; not shown (it cannot be checked)")
    raise UsageError(f"{what} is a binary file ({route.kind}); not shown")


def show_file(runner: GitRunner, path: str, ref: str, options: scan_mod.ScanOptions) -> str:
    """The text of `path` at `ref` with every secret span masked."""
    rel = _repo_relative(path)
    listing = runner.run(["ls-tree", "-z", "--full-tree", ref, "--", rel]).decode(
        "utf-8", "surrogateescape"
    )
    oid = ""
    for record in listing.split("\x00"):
        meta, _, name = record.partition("\t")
        if name != rel:
            continue
        mode, otype, entry_oid = meta.split(" ")
        if otype != "blob" or mode not in _BLOB_MODES:
            raise UsageError(f"{rel} at {ref} is not a regular file")
        oid = entry_oid
    if not oid:
        raise UsageError(f"{rel} does not exist at {ref}")
    content = runner.run(["cat-file", "blob", oid])
    text = _text_or_refuse(content, max_scan_mb=options.max_scan_mb, what=rel)
    return mask_secret_spans(text, scan_mod.detect_secrets_in_text(text, rel, options))


@dataclass(frozen=True, slots=True)
class RedactResult:
    rule_id: str
    line: int
    column: int


def _spans_matching(detections: list[Detection], blob: str, selector: str) -> list[Detection]:
    """Detections whose finding fingerprint (for this file's blob) or secret group id
    is `selector`, one per distinct span."""
    matches: dict[tuple[int, int], Detection] = {}
    for det in detections:
        fingerprint = make_fingerprint(
            rule_id=det.rule_id,
            kind="blob",
            location_key=f"{blob}:{det.line}:{det.col}",
            value=det.value,
        )
        group_id = make_group_id(
            category=det.category, rule_id=det.rule_id, normalized_value=det.value
        )
        if selector in (fingerprint, group_id):
            matches.setdefault((det.start, det.end), det)
    return list(matches.values())


def redact_file(
    path: Path, finding: str, placeholder: str, options: scan_mod.ScanOptions
) -> RedactResult:
    """Replace the one secret span identified by `finding` (a fingerprint recomputed
    for this file's content, or a secret group id) with `placeholder`, in place."""
    if not placeholder:
        raise UsageError("--with must not be empty")
    if path.is_symlink() or not path.is_file():
        raise UsageError(f"not a regular working-tree file: {path}")
    content = path.read_bytes()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise UsageError(f"{path} is not valid UTF-8; edit it by hand") from None
    if b"\x00" in content:
        raise UsageError(f"{path} is a binary file; edit it by hand")

    detections = scan_mod.detect_secrets_in_text(text, path.as_posix(), options)
    matches = _spans_matching(detections, blob_id(content), finding)
    if not matches:
        raise UsageError(f"no secret in {path} matches {finding!r}")
    if len(matches) > 1:
        raise UsageError(
            f"{finding!r} matches {len(matches)} spans in {path}; "
            "use a single finding's fingerprint, or edit the file by hand"
        )
    (match,) = matches
    updated = text[: match.start] + placeholder + text[match.end :]
    path.write_bytes(updated.encode("utf-8"))
    return RedactResult(rule_id=match.rule_id, line=match.line, column=match.col)
