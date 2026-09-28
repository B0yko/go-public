"""The plant-placement engine: a `git fast-import` stream builder plus resolution.

`FixtureContext` is the one thing `bench/fixture.py` and every later
`bench/plants/<category>.py` module share: methods to place content at each of the
15 location types the product spec names, and a two-phase build (emit the whole
`fast-import` stream, then resolve every placement to a concrete blob/commit/tag id
once the import has run). See `_work/go-public/specs/fixture-api.md` for the full
reference; only neutral "marker" plants exist so far (stage 1b).

Only `git/runner.py` may run git directly; this module only ever calls it through a
`GitRunner` bound to the `fixture` role, never `subprocess` itself.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from go_public.bench.truth import ExpectedFinding, TruthEntry
from go_public.git.runner import GitRunner

LocationType = Literal[
    "head",
    "history_only",
    "side_branch",
    "tag_only",
    "notes",
    "stash",
    "remote_tracking",
    "replace",
    "original",
    "commit_message",
    "tag_message",
    "ref_name",
    "path_name",
    "binary_field",
    "unreachable",
]

#: Every location type the API supports, for callers that need to enumerate them.
LOCATION_TYPES: tuple[LocationType, ...] = (
    "head",
    "history_only",
    "side_branch",
    "tag_only",
    "notes",
    "stash",
    "remote_tracking",
    "replace",
    "original",
    "commit_message",
    "tag_message",
    "ref_name",
    "path_name",
    "binary_field",
    "unreachable",
)

Identity = tuple[str, str]  # (name, email)

#: A ref only fast-import needs, never reachable from any branch once resolved:
#: its holding branch is deleted after the commit it needs has been made.
_ORPHAN_PREFIX = "refs/heads/_fixture/orphan-"


def blob_id(content: bytes) -> str:
    """The blob object id git would assign this content, without asking git.

    sha1(f"blob {len(content)}\\0" + data) — architecture.md "Fixture & truth":
    never assume cross-platform blob ids, but this hash *is* the git blob id on
    every platform, since it only depends on the bytes we chose ourselves.
    """
    header = f"blob {len(content)}\0".encode()
    return hashlib.sha1(header + content).hexdigest()  # noqa: S324 (git's own object hash)


@dataclass
class Plant:
    """One planted piece of content, described before the repository exists.

    `bench/plants/<category>.py` modules build these and pass them to
    `FixtureContext.place`. `category`/`eval_class`/`rule_family` are opaque to the
    engine; it only interprets `location_type`. `expected_extra` lists secondary
    findings the plant must also produce (e.g. a `.env` plant's sensitive-file
    finding alongside its secret finding).
    """

    plant_id: str
    category: str
    location_type: LocationType
    content: bytes = b""
    path: str | None = None
    message: str | None = None
    ref_name: str | None = None
    field_name: str | None = None
    author: Identity | None = None
    eval_class: str | None = None
    rule_family: str | None = None
    expected_extra: list[ExpectedFinding] = field(default_factory=list)


@dataclass
class ResolvedPlant:
    """A `Plant` after import: concrete ids, ready for `truth.jsonl` or assertions."""

    plant: Plant
    kind: str
    key: dict[str, str | int]
    at_export_ref: bool
    ref: str | None = None
    commit: str | None = None
    blob: str | None = None

    def truth_entry(self) -> TruthEntry:
        expected = [
            ExpectedFinding(
                category=self.plant.category,
                eval_class=self.plant.eval_class or self.plant.category,
                kind=self.kind,
                key=self.key,
            ),
            *self.plant.expected_extra,
        ]
        return TruthEntry(
            plant_id=self.plant.plant_id,
            category=self.plant.category,
            eval_class=self.plant.eval_class,
            location_type=self.plant.location_type,
            at_export_ref=self.at_export_ref,
            rule_family=self.plant.rule_family,
            expected=expected,
        )


_Resolver = Callable[[dict[str, str], dict[str, str]], ResolvedPlant]
_RefUpdate = Callable[[dict[str, str]], tuple[str, str]]


class FixtureContext:
    """Accumulates a `fast-import` stream and the plants placed on it.

    Usage: build filler/topology with `blob`/`commit`/`reset`, call `place` for each
    plant, then `render_stream()` to get the bytes to feed `git fast-import
    --export-marks=...`, and finally `finalize(runner, mark_to_oid)` once the import
    has run (it deletes orphan branches, creates tags and deferred refs, and returns
    every plant's `ResolvedPlant`).
    """

    def __init__(self, *, public_identity: Identity, base_when: int) -> None:
        self.public_identity = public_identity
        self._when = base_when
        self._parts: list[bytes] = []
        self._next_mark = 0
        self.branch_tip: dict[str, str] = {}
        self._orphans_to_delete: list[str] = []
        self._tag_requests: list[tuple[str, str, str | None, Identity, int]] = []
        self._ref_updates: list[_RefUpdate] = []
        self._pending: list[_Resolver] = []

    # -- low-level stream building -------------------------------------------------

    def next_when(self) -> int:
        self._when += 60
        return self._when

    def _mark(self) -> str:
        self._next_mark += 1
        return f":{self._next_mark}"

    def blob(self, content: bytes) -> str:
        """Emit a `blob` command and return its mark (`git`'s own oid is never asked
        for: content-addressing means `blob_id(content)` already gives it)."""
        mark = self._mark()
        self._parts.append(f"blob\nmark {mark}\ndata {len(content)}\n".encode() + content + b"\n")
        return mark

    def commit(
        self,
        ref: str,
        *,
        message: str,
        files: dict[str, str | None],
        author: Identity | None = None,
        when: int | None = None,
        from_: str | None = None,
        merges: tuple[str, ...] = (),
    ) -> str:
        """Emit a `commit` command. `files` maps path -> blob mark, or None to delete.

        `from_` branches off an explicit mark (e.g. a different ref's tip); left as
        `None`, the commit auto-chains from this same ref's current tip in this
        stream, or becomes a root commit the first time `ref` is used.
        """
        mark = self._mark()
        ident = author or self.public_identity
        ts = when if when is not None else self.next_when()
        lines = [f"commit {ref}", f"mark {mark}"]
        lines.append(f"author {ident[0]} <{ident[1]}> {ts} +0000")
        lines.append(f"committer {ident[0]} <{ident[1]}> {ts} +0000")
        head = ("\n".join(lines) + "\n").encode()
        msg = message.encode()
        head += f"data {len(msg)}\n".encode() + msg + b"\n"
        resolved_from = from_ if from_ is not None else self.branch_tip.get(ref)
        if resolved_from is not None:
            head += f"from {resolved_from}\n".encode()
        for merge_mark in merges:
            head += f"merge {merge_mark}\n".encode()
        for path, blobref in files.items():
            if blobref is None:
                head += f"D {path}\n".encode()
            else:
                head += f"M 100644 {blobref} {path}\n".encode()
        head += b"\n"
        self._parts.append(head)
        self.branch_tip[ref] = mark
        return mark

    def reset(self, ref: str, *, from_: str) -> None:
        """Point `ref` at an existing mark/oid without creating a new commit."""
        self._parts.append(f"reset {ref}\nfrom {from_}\n".encode())
        self.branch_tip[ref] = from_

    def render_stream(self) -> bytes:
        return b"".join(self._parts)

    # -- post-import bookkeeping -----------------------------------------------

    def request_tag(self, name: str, target: str, *, message: str | None, author: Identity) -> str:
        """Queue a tag (annotated if `message` is given, else lightweight).

        Returns a `"tag:<name>"` token; a plant's resolver looks up the real tag
        (or, for a lightweight tag, commit) oid in the `tag_oids` map `finalize`
        builds, keyed by this same name.
        """
        self._tag_requests.append((name, target, message, author, self.next_when()))
        return f"tag:{name}"

    def delete_after_import(self, ref: str) -> None:
        """Delete a ref (typically an orphan-staging branch) once import is done."""
        self._orphans_to_delete.append(ref)

    def update_ref_after_import(self, resolver: _RefUpdate) -> None:
        """Queue `update-ref <name> <target>`, both resolved from marks/tag oids."""
        self._ref_updates.append(resolver)

    def orphan_branch(self, plant_id: str) -> str:
        """A throwaway branch name for a commit meant to end up on no branch."""
        ref = f"{_ORPHAN_PREFIX}{plant_id}"
        self.delete_after_import(ref)
        return ref

    # -- plant placement -------------------------------------------------------

    def place(self, plant: Plant) -> None:
        """Dispatch to the `_place_<location_type>` method for this plant."""
        method = getattr(self, f"_place_{plant.location_type}")
        method(plant)

    def _queue(self, resolver: _Resolver) -> None:
        self._pending.append(resolver)

    def _blob_commit(
        self, plant: Plant, ref: str, path: str, *, from_: str | None = None
    ) -> tuple[str, str]:
        blob_mark = self.blob(plant.content)
        commit_mark = self.commit(
            ref,
            message=plant.message or f"chore: add {path}",
            files={path: blob_mark},
            author=plant.author,
            from_=from_,
        )
        return commit_mark, blob_id(plant.content)

    def _place_head(self, plant: Plant) -> None:
        path = plant.path or f"markers/{plant.plant_id}.txt"
        ref = "refs/heads/main"
        commit_mark, blob = self._blob_commit(plant, ref, path)

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="blob",
                key={"blob": blob, "line": 1},
                at_export_ref=True,
                ref=ref,
                commit=marks[commit_mark],
                blob=blob,
            )

        self._queue(resolve)

    def _place_path_name(self, plant: Plant) -> None:
        path = plant.path or f"markers/{plant.plant_id}/file.txt"
        ref = "refs/heads/main"
        commit_mark, blob = self._blob_commit(plant, ref, path)

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="path",
                key={"path": path},
                at_export_ref=True,
                ref=ref,
                commit=marks[commit_mark],
                blob=blob,
            )

        self._queue(resolve)

    def _place_binary_field(self, plant: Plant) -> None:
        path = plant.path or f"markers/{plant.plant_id}.bin"
        ref = "refs/heads/main"
        commit_mark, blob = self._blob_commit(plant, ref, path)
        field_name = plant.field_name or "field"

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="binary_field",
                key={"blob": blob, "field": field_name},
                at_export_ref=True,
                ref=ref,
                commit=marks[commit_mark],
                blob=blob,
            )

        self._queue(resolve)

    def _place_history_only(self, plant: Plant) -> None:
        path = plant.path or f"markers/{plant.plant_id}.txt"
        ref = "refs/heads/main"
        commit_mark, blob = self._blob_commit(plant, ref, path)
        self.commit(
            ref,
            message=f"chore: remove {path}",
            files={path: None},
            author=plant.author,
        )

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="blob",
                key={"blob": blob, "line": 1},
                at_export_ref=False,
                ref=ref,
                commit=marks[commit_mark],
                blob=blob,
            )

        self._queue(resolve)

    def _place_side_branch(self, plant: Plant) -> None:
        path = plant.path or f"markers/{plant.plant_id}.txt"
        ref = plant.ref_name or "refs/heads/side/experiment"
        commit_mark, blob = self._blob_commit(plant, ref, path)

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="blob",
                key={"blob": blob, "line": 1},
                at_export_ref=False,
                ref=ref,
                commit=marks[commit_mark],
                blob=blob,
            )

        self._queue(resolve)

    def _place_tag_only(self, plant: Plant) -> None:
        path = plant.path or f"markers/{plant.plant_id}.txt"
        orphan_ref = self.orphan_branch(plant.plant_id)
        commit_mark, blob = self._blob_commit(plant, orphan_ref, path, from_=None)
        tag_name = plant.ref_name or f"tag-only-{plant.plant_id}"
        self.request_tag(
            tag_name,
            commit_mark,
            message="tagged release",
            author=plant.author or self.public_identity,
        )

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="blob",
                key={"blob": blob, "line": 1},
                at_export_ref=False,
                ref=f"refs/tags/{tag_name}",
                commit=marks[commit_mark],
                blob=blob,
            )

        self._queue(resolve)

    def _place_notes(self, plant: Plant) -> None:
        ref = "refs/notes/commits"
        path = plant.path or f"{plant.plant_id}.txt"
        commit_mark, blob = self._blob_commit(plant, ref, path, from_=None)

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="blob",
                key={"blob": blob, "line": 1},
                at_export_ref=False,
                ref=ref,
                commit=marks[commit_mark],
                blob=blob,
            )

        self._queue(resolve)

    def _place_stash(self, plant: Plant) -> None:
        ref = "refs/stash"
        path = plant.path or f"{plant.plant_id}.txt"
        commit_mark, blob = self._blob_commit(plant, ref, path, from_=None)

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="blob",
                key={"blob": blob, "line": 1},
                at_export_ref=False,
                ref=ref,
                commit=marks[commit_mark],
                blob=blob,
            )

        self._queue(resolve)

    def _place_remote_tracking(self, plant: Plant) -> None:
        ref = plant.ref_name or f"refs/remotes/origin/{plant.plant_id}"
        path = plant.path or f"{plant.plant_id}.txt"
        commit_mark, blob = self._blob_commit(plant, ref, path, from_=None)

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="blob",
                key={"blob": blob, "line": 1},
                at_export_ref=False,
                ref=ref,
                commit=marks[commit_mark],
                blob=blob,
            )

        self._queue(resolve)

    def _place_replace(self, plant: Plant) -> None:
        path = plant.path or f"markers/{plant.plant_id}.txt"
        orphan_ref = self.orphan_branch(plant.plant_id)
        commit_mark, blob = self._blob_commit(plant, orphan_ref, path, from_=None)
        old_target = self.branch_tip.get("refs/heads/main")
        if old_target is None:
            raise RuntimeError("replace plants need at least one commit on main first")

        def ref_update(marks: dict[str, str]) -> tuple[str, str]:
            return f"refs/replace/{marks[old_target]}", marks[commit_mark]

        self.update_ref_after_import(ref_update)

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="blob",
                key={"blob": blob, "line": 1},
                at_export_ref=False,
                ref=f"refs/replace/{marks[old_target]}",
                commit=marks[commit_mark],
                blob=blob,
            )

        self._queue(resolve)

    def _place_original(self, plant: Plant) -> None:
        path = plant.path or f"markers/{plant.plant_id}.txt"
        orphan_ref = self.orphan_branch(plant.plant_id)
        commit_mark, blob = self._blob_commit(plant, orphan_ref, path, from_=None)
        ref = "refs/original/refs/heads/main"

        def ref_update(marks: dict[str, str]) -> tuple[str, str]:
            return ref, marks[commit_mark]

        self.update_ref_after_import(ref_update)

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="blob",
                key={"blob": blob, "line": 1},
                at_export_ref=False,
                ref=ref,
                commit=marks[commit_mark],
                blob=blob,
            )

        self._queue(resolve)

    def _place_commit_message(self, plant: Plant) -> None:
        ref = "refs/heads/main"
        message = plant.message or "chore: marker commit"
        commit_mark = self.commit(ref, message=message, files={}, author=plant.author)

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            commit = marks[commit_mark]
            return ResolvedPlant(
                plant=plant,
                kind="commit_message",
                key={"commit": commit},
                at_export_ref=True,
                ref=ref,
                commit=commit,
            )

        self._queue(resolve)

    def _place_tag_message(self, plant: Plant) -> None:
        target = self.branch_tip.get("refs/heads/main")
        if target is None:
            raise RuntimeError("tag_message plants need at least one commit on main first")
        tag_name = plant.ref_name or f"tag-message-{plant.plant_id}"
        message = plant.message or "tagged release"
        author = plant.author or self.public_identity
        self.request_tag(tag_name, target, message=message, author=author)

        def resolve(_marks: dict[str, str], tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="tag_message",
                key={"tag": tags[tag_name]},
                at_export_ref=False,
                ref=f"refs/tags/{tag_name}",
                commit=None,
            )

        self._queue(resolve)

    def _place_ref_name(self, plant: Plant) -> None:
        target = self.branch_tip.get("refs/heads/main")
        if target is None:
            raise RuntimeError("ref_name plants need at least one commit on main first")
        ref = plant.ref_name or f"refs/heads/markers/{plant.plant_id}"
        self.reset(ref, from_=target)

        def resolve(marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="ref_name",
                key={"ref": ref},
                at_export_ref=False,
                ref=ref,
                commit=marks[target],
            )

        self._queue(resolve)

    def _place_unreachable(self, plant: Plant) -> None:
        self.blob(plant.content)  # never referenced by any commit: stays dangling
        blob = blob_id(plant.content)

        def resolve(_marks: dict[str, str], _tags: dict[str, str]) -> ResolvedPlant:
            return ResolvedPlant(
                plant=plant,
                kind="unreachable_blob",
                key={"blob": blob, "line": 1},
                at_export_ref=False,
                blob=blob,
            )

        self._queue(resolve)

    # -- finalisation ------------------------------------------------------------

    def finalize(self, runner: GitRunner, mark_to_oid: dict[str, str]) -> list[ResolvedPlant]:
        """Run every post-import op and resolve every queued plant.

        Order matters: orphan branches are deleted first (so nothing but the tags
        and refs created below can still reach them), then tags, then deferred
        `update-ref` calls, all through the `fixture`-role runner.
        """
        for ref in self._orphans_to_delete:
            runner.run(["update-ref", "-d", ref])

        tag_oids: dict[str, str] = {}
        for name, target, message, author, when in self._tag_requests:
            target_oid = mark_to_oid[target]
            if message is None:
                tag_oids[name] = target_oid
            else:
                tag_oids[name] = self._create_annotated_tag(
                    runner, name, target_oid, message=message, author=author, when=when
                )
            runner.run(["update-ref", f"refs/tags/{name}", tag_oids[name]])

        for ref_update in self._ref_updates:
            ref_name, target = ref_update(mark_to_oid)
            runner.run(["update-ref", ref_name, target])

        return [resolver(mark_to_oid, tag_oids) for resolver in self._pending]

    @staticmethod
    def _create_annotated_tag(
        runner: GitRunner,
        name: str,
        target_oid: str,
        *,
        message: str,
        author: Identity,
        when: int,
    ) -> str:
        """Build the raw tag object ourselves and write it with `hash-object`.

        `fixture`'s allowlist has no porcelain `tag` command; `objects.parse_tag`
        fixes the exact raw shape this must match.
        """
        raw = (
            f"object {target_oid}\n"
            "type commit\n"
            f"tag {name}\n"
            f"tagger {author[0]} <{author[1]}> {when} +0000\n"
            "\n"
            f"{message}\n"
        ).encode()
        out = runner.run(["hash-object", "-t", "tag", "-w", "--stdin"], input=raw)
        return out.decode().strip()
