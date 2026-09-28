"""Build a complete inventory of a repository: every ref, commit, tag and blob.

See architecture.md "Git runner" and "Objects & inventory" for the exact commands.
Everything here reads through a `source`-role :class:`GitRunner`; nothing writes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from go_public.errors import UnsupportedRepo
from go_public.git.objects import CatFileBatch, CommitObj, TagObj, parse_commit, parse_tag
from go_public.git.runner import GitRunner

RefKind = str  # "branch" | "tag" | "remote" | "notes" | "stash" | "replace" | "original" | "other"

_LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1"
_LFS_CANDIDATE_MAX_SIZE = 1024


@dataclass(frozen=True)
class Ref:
    name: str
    kind: RefKind
    target: str
    target_type: str
    peeled: str | None


@dataclass(frozen=True)
class BlobOccurrence:
    blob: str
    path: str
    mode: str
    commit: str
    #: The blob this path held at `commit`'s parent side of the diff, or `""` for an
    #: addition (stage-3.md "3b": `detect/licence.py`'s transition tracking needs both
    #: sides of a diff entry to compare old vs. new licence identification, without a
    #: second full-history `git log` pass).
    old_blob: str = ""


@dataclass(frozen=True)
class GitlinkOccurrence:
    oid: str
    path: str
    commit: str


@dataclass(frozen=True)
class RepoState:
    bare: bool
    object_format: str
    shallow: bool
    partial_clone: bool


@dataclass(frozen=True)
class Warning:
    code: str
    message: str


@dataclass
class Inventory:
    refs: list[Ref]
    commits: dict[str, CommitObj]
    tags: dict[str, TagObj]
    occurrences: list[BlobOccurrence]
    gitlinks: list[GitlinkOccurrence]
    blob_sizes: dict[str, int]
    unreachable_blobs: dict[str, int]
    export_tree: dict[str, tuple[str, str]]  # path -> (mode, blob)
    repo_state: RepoState
    missing_objects: list[str]
    lfs_pointers: set[str]
    uncommitted_changes: bool
    warnings: list[Warning]
    head_only: bool = False
    _refs_containing_cache: dict[str, list[str]] = field(default_factory=dict, repr=False)

    @property
    def total_bytes(self) -> int:
        return sum(self.blob_sizes.values())

    def present_at_export_ref(self, blob: str) -> bool:
        return any(b == blob for _mode, b in self.export_tree.values())

    def summary_line(self) -> str:
        line = (
            f"inventory: {len(self.refs)} refs, {len(self.commits)} commits, "
            f"{len(self.tags)} tags, {len(self.blob_sizes)} unique blobs, "
            f"{self.total_bytes} bytes"
        )
        if self.unreachable_blobs:
            line += f", {len(self.unreachable_blobs)} unreachable blobs"
        return line

    def refs_containing(self, commit: str) -> list[str]:
        """Refs whose history includes `commit`. Computed lazily and cached per commit."""
        if commit in self._refs_containing_cache:
            return self._refs_containing_cache[commit]
        heads = self._ref_heads()
        result = [name for name, head in heads.items() if self._reaches(head, commit)]
        self._refs_containing_cache[commit] = result
        return result

    def _ref_heads(self) -> dict[str, str]:
        heads: dict[str, str] = {}
        for ref in self.refs:
            head = ref.peeled or ref.target
            if head in self.commits:
                heads[ref.name] = head
        return heads

    def _reaches(self, start: str, target: str) -> bool:
        seen: set[str] = set()
        stack = [start]
        while stack:
            oid = stack.pop()
            if oid == target:
                return True
            if oid in seen:
                continue
            seen.add(oid)
            commit = self.commits.get(oid)
            if commit is not None:
                stack.extend(commit.parents)
        return False


def _kind_for_ref(name: str) -> RefKind:
    if name.startswith("refs/heads/"):
        return "branch"
    if name.startswith("refs/tags/"):
        return "tag"
    if name.startswith("refs/remotes/"):
        return "remote"
    if name.startswith("refs/notes/"):
        return "notes"
    if name == "refs/stash":
        return "stash"
    if name.startswith("refs/replace/"):
        return "replace"
    if name.startswith("refs/original/"):
        return "original"
    return "other"


def _check_object_format(runner: GitRunner) -> str:
    out = runner.run(["rev-parse", "--show-object-format"]).decode().strip()
    if out == "sha256":
        raise UnsupportedRepo("sha256 object-format repositories are not supported yet (roadmap)")
    return out or "sha1"


def _is_bare(runner: GitRunner) -> bool:
    return runner.run(["rev-parse", "--is-bare-repository"]).decode().strip() == "true"


def _is_shallow(runner: GitRunner) -> bool:
    return runner.run(["rev-parse", "--is-shallow-repository"]).decode().strip() == "true"


def _is_partial_clone(runner: GitRunner) -> bool:
    proc_out = runner.run(["config", "--get", "extensions.partialclone"], check=False)
    return proc_out.decode().strip() != ""


def _read_refs(runner: GitRunner) -> list[Ref]:
    fmt = "%(refname)%00%(objectname)%00%(objecttype)%00%(*objectname)%00%(*objecttype)"
    out = runner.run(["for-each-ref", f"--format={fmt}"]).decode("utf-8", "replace")
    refs: list[Ref] = []
    for line in out.splitlines():
        if not line:
            continue
        name, oid, otype, peeled, _peeled_type = line.split("\x00")
        refs.append(
            Ref(
                name=name,
                kind=_kind_for_ref(name),
                target=oid,
                target_type=otype,
                peeled=peeled or None,
            )
        )
    return refs


def _list_all_commit_and_tag_oids(
    runner: GitRunner, refs: list[Ref]
) -> tuple[list[str], list[str]]:
    """Commit oids reachable via `rev-list --all`, and annotated tag object oids."""
    commit_oids = [line for line in runner.run(["rev-list", "--all"]).decode().splitlines() if line]
    tag_oids = [ref.target for ref in refs if ref.target_type == "tag"]
    return commit_oids, tag_oids


def _parse_raw_log(data: bytes) -> list[tuple[str, list[tuple[str, str, str, str, str]]]]:
    """Parse `log --all --raw -z --format=%x00%H%x00` output.

    Returns `(commit, [(new_mode, old_blob, new_blob, status, path), ...])` per
    commit. A run of diff-entry tokens for a commit is always followed by an empty
    token that precedes Git's `--format` machinery always appends its own NUL record
    terminator in `-z` mode, on top of whatever the format string itself already
    printed, and the hard-coded blank line git prints before a diff survives as a
    literal `\n` even in `-z` mode. So each commit is `"" HASH "" ("\n:status" PATH)*`
    when the whole stream is split on NUL: an empty token, the hash, a second empty
    token (the format's own terminator plus git's), then zero or more (status-line,
    path) pairs whose status line carries a stray leading newline.

    `old_blob` (the diff's `:old_mode new_mode old_sha new_sha status` field 3) is
    kept alongside the new blob so a detector can compare a path's before/after
    content for one diff entry without a second history pass (stage-3.md 3b:
    `detect/licence.py`'s transition tracking).
    """
    toks = data.split(b"\x00")
    i = 0
    n = len(toks)
    result: list[tuple[str, list[tuple[str, str, str, str, str]]]] = []
    while i < n:
        if toks[i] != b"":
            break  # malformed / trailing data; stop rather than misparse
        i += 1
        if i >= n:
            break
        commit_hash = toks[i].decode()
        i += 1
        if i >= n or toks[i] != b"":
            break  # malformed: expected the format's own record terminator
        i += 1
        entries: list[tuple[str, str, str, str, str]] = []
        while i < n and toks[i] != b"":
            statusline = toks[i].decode().lstrip("\n")
            i += 1
            if i >= n:
                break
            path = toks[i].decode("utf-8", "replace")
            i += 1
            parts = statusline.split(" ")
            if len(parts) >= 5:
                new_mode, old_sha, new_sha, status = parts[1], parts[2], parts[3], parts[4]
                entries.append((new_mode, old_sha, new_sha, status, path))
        result.append((commit_hash, entries))
    return result


_ZERO_OID_PREFIXES = ("0000000",)


def _attribute_blobs(
    runner: GitRunner,
) -> tuple[list[BlobOccurrence], list[GitlinkOccurrence]]:
    args = [
        "log",
        "--all",
        "--raw",
        "--no-renames",
        "--no-abbrev",
        "--diff-merges=separate",
        "-z",
        "--format=%x00%H%x00",
    ]
    data = runner.run(args)
    occurrences: list[BlobOccurrence] = []
    gitlinks: list[GitlinkOccurrence] = []
    for commit_hash, entries in _parse_raw_log(data):
        for new_mode, old_sha, new_sha, status, path in entries:
            if status == "D" or new_sha.startswith(_ZERO_OID_PREFIXES):
                continue
            if new_mode == "160000":
                gitlinks.append(GitlinkOccurrence(oid=new_sha, path=path, commit=commit_hash))
                continue
            old_blob = "" if old_sha.startswith(_ZERO_OID_PREFIXES) else old_sha
            occurrences.append(
                BlobOccurrence(
                    blob=new_sha, path=path, mode=new_mode, commit=commit_hash, old_blob=old_blob
                )
            )
    return occurrences, gitlinks


def _blob_sizes(runner: GitRunner, blob_ids: set[str]) -> dict[str, int]:
    sizes: dict[str, int] = {}
    if not blob_ids:
        return sizes
    with CatFileBatch(runner, check_only=True) as batch:
        for oid in blob_ids:
            result = batch.check(oid)
            if result is not None and result[0] == "blob":
                sizes[oid] = result[1]
    return sizes


def _unreachable_blobs(runner: GitRunner, known: set[str]) -> dict[str, int]:
    out = runner.run(["cat-file", "--batch-all-objects", "--batch-check"]).decode(
        "utf-8", "replace"
    )
    unreachable: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        oid, otype, size = parts
        if otype == "blob" and oid not in known:
            unreachable[oid] = int(size)
    return unreachable


def _export_tree(runner: GitRunner, export_ref: str) -> dict[str, tuple[str, str]]:
    out = runner.run(["ls-tree", "-r", "-z", "--full-tree", export_ref]).decode("utf-8", "replace")
    tree: dict[str, tuple[str, str]] = {}
    for entry in out.split("\x00"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        mode, _otype, oid = meta.split(" ")
        tree[path] = (mode, oid)
    return tree


def _missing_objects(runner: GitRunner) -> list[str]:
    out = runner.run(["rev-list", "--all", "--objects", "--missing=print"]).decode(
        "utf-8", "replace"
    )
    missing = []
    for line in out.splitlines():
        if line.startswith("?"):
            missing.append(line[1:].split()[0])
    return missing


def _find_lfs_pointers(runner: GitRunner, blob_sizes: dict[str, int]) -> set[str]:
    candidates = [oid for oid, size in blob_sizes.items() if size <= _LFS_CANDIDATE_MAX_SIZE]
    if not candidates:
        return set()
    found: set[str] = set()
    with CatFileBatch(runner) as batch:
        for oid in candidates:
            result = batch.get(oid)
            if result is not None and result[1].startswith(_LFS_POINTER_PREFIX):
                found.add(oid)
    return found


def build(
    runner: GitRunner,
    *,
    include_unreachable: bool = False,
    export_ref: str = "HEAD",
) -> Inventory:
    """Build the full inventory: every ref, commit, annotated tag and unique blob."""
    object_format = _check_object_format(runner)
    bare = _is_bare(runner)
    shallow = _is_shallow(runner)
    partial_clone = _is_partial_clone(runner)
    repo_state = RepoState(
        bare=bare, object_format=object_format, shallow=shallow, partial_clone=partial_clone
    )

    refs = _read_refs(runner)
    commit_oids, tag_oids = _list_all_commit_and_tag_oids(runner, refs)

    commits: dict[str, CommitObj] = {}
    with CatFileBatch(runner) as batch:
        for oid in commit_oids:
            got = batch.get(oid)
            if got is not None and got[0] == "commit":
                commits[oid] = parse_commit(oid, got[1])

    tags: dict[str, TagObj] = {}
    with CatFileBatch(runner) as batch:
        for oid in tag_oids:
            got = batch.get(oid)
            if got is not None and got[0] == "tag":
                tags[oid] = parse_tag(oid, got[1])

    occurrences, gitlinks = _attribute_blobs(runner)
    unique_blob_ids = {occ.blob for occ in occurrences}
    blob_sizes = _blob_sizes(runner, unique_blob_ids)

    unreachable_blobs: dict[str, int] = {}
    if include_unreachable:
        unreachable_blobs = _unreachable_blobs(runner, unique_blob_ids)

    export_tree = _export_tree(runner, export_ref)
    missing_objects = _missing_objects(runner)
    lfs_pointers = _find_lfs_pointers(runner, blob_sizes)

    uncommitted_changes = False
    if not bare:
        status_out = runner.run(["status", "--porcelain"]).decode("utf-8", "replace")
        uncommitted_changes = bool(status_out.strip())

    warnings: list[Warning] = []
    if shallow:
        warnings.append(Warning("shallow-clone", "repository is a shallow clone"))
    if missing_objects:
        warnings.append(
            Warning(
                "missing-objects",
                f"{len(missing_objects)} object(s) are missing (partial clone); not fetched",
            )
        )
    if lfs_pointers:
        warnings.append(
            Warning(
                "lfs-pointers",
                f"{len(lfs_pointers)} blob(s) are Git LFS pointers; LFS content is not scanned",
            )
        )
    if uncommitted_changes:
        warnings.append(Warning("uncommitted-changes", "working tree or index differs from HEAD"))

    return Inventory(
        refs=refs,
        commits=commits,
        tags=tags,
        occurrences=occurrences,
        gitlinks=gitlinks,
        blob_sizes=blob_sizes,
        unreachable_blobs=unreachable_blobs,
        export_tree=export_tree,
        repo_state=repo_state,
        missing_objects=missing_objects,
        lfs_pointers=lfs_pointers,
        uncommitted_changes=uncommitted_changes,
        warnings=warnings,
    )


def build_head_only(runner: GitRunner, *, export_ref: str = "HEAD") -> Inventory:
    """Scan only the tree at `export_ref`: no history, messages or identities."""
    object_format = _check_object_format(runner)
    bare = _is_bare(runner)
    repo_state = RepoState(
        bare=bare, object_format=object_format, shallow=False, partial_clone=False
    )
    export_tree = _export_tree(runner, export_ref)
    blob_ids = {oid for _mode, oid in export_tree.values()}
    blob_sizes = _blob_sizes(runner, blob_ids)
    return Inventory(
        refs=[],
        commits={},
        tags={},
        occurrences=[],
        gitlinks=[],
        blob_sizes=blob_sizes,
        unreachable_blobs={},
        export_tree=export_tree,
        repo_state=repo_state,
        missing_objects=[],
        lfs_pointers=set(),
        uncommitted_changes=False,
        warnings=[],
        head_only=True,
    )
