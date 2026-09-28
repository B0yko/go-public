"""The secrets engine: the ported gitleaks v8.30.1 rule matcher plus go-public's own
generic-entropy assignment detector.

Ports the matching semantics of gitleaks's `detect` package at the pinned tag
(https://github.com/gitleaks/gitleaks/blob/v8.30.1/detect/detect.go and
.../detect/utils.go): keyword prefiltering, `secretGroup` extraction, entropy
gating, global-then-rule allowlist evaluation (`checkCommitOrPathAllowed` /
`checkFindingAllowed`, including `regexTarget`/`condition`/stopwords), path-only
rules, required multi-part rules (`processRequiredRules` / `withinProximity`),
`skipReport`, and the generic-vs-specific overlap filter (`detect/utils.go filter`).
See docs/adr/0002-re2-and-ported-gitleaks-semantics.md for what is and is not ported.

Not ported (documented differences from gitleaks itself):
- base64/hex/percent decoding passes (gitleaks's `detect/codec`) — gitleaks decodes
  up to depth 5 by default; go-public does not decode at all.
- `gitleaks:allow` inline comments — suppression is go-public's own
  `go-public:allow <reason>`, applied later in `suppress.py`, not here.
- SCM links, SARIF/CLI report plumbing, colourised printing.

Path- and commit-dependent parts (a rule's own `path`, an allowlist's `paths`/
`commits`, the generic-entropy lockfile skip) are evaluated separately from content
matching: `scan_content()` runs the keyword prefilter, regex matching, `secretGroup`
extraction, entropy gating and required-rule proximity exactly once per blob's text,
producing path/commit-independent candidates; `filter_occurrence()` then applies
every path/commit-dependent decision (including the global and per-rule allowlists,
which need the concrete `(path, commit)` pair) to one occurrence's candidates,
without re-running any regex. A blob attributed to several (path, commit) pairs
therefore has its content matched exactly once, no matter how many occurrences the
scan pipeline (`scan.py`) evaluates it for (stage-3a fix for a stage-2b deviation:
see STATUS.md and `docs/adr/0001-blob-level-scanning.md`). `detect()` remains as a
convenience that runs both phases for one text/occurrence in a single call, for
callers (and tests) that only ever see one occurrence at a time.

One deliberate scope limit from this split: a `required`-composite rule's own
proximity check (`_apply_required_content`) and its sub-rule's matches are now
resolved once per blob, ignoring any `path` filter on the primary or the required
sub-rule; only the primary rule's own `path` is (still) applied afterwards, per
occurrence. No rule in the bundled config (v8.30.1) combines `required` with a
`path` filter on either side, so this has no effect on it; a custom `--gitleaks-config`
that combines the two would see a candidate survive content-scan and then get
filtered per occurrence anyway if the primary's own `path` fails to match.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import PurePosixPath

import re2

from go_public.detect.base import Detection, UnitCtx
from go_public.detect.gitleaks_config import Allowlist, GitleaksConfig, Required, Rule

#: go-public's own lockfile skip for the generic-entropy detector (product spec
#: item 2). Vendor rules are unaffected; the bundled gitleaks allowlist already
#: excludes most of these by path pattern for its own rules.
_LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
        "Gemfile.lock",
        "composer.lock",
        "go.sum",
    }
)

_MAX_GENERIC_LINE_CHARS = 1000

#: `key|secret|token|passw(or)?d|pwd|credential|auth`, then an assignment operator,
#: then a token of at least 16 characters from a typical secret-value alphabet.
#: go-public's own pattern (not from gitleaks.toml); see product spec item 2 and
#: stage-2.md. Deliberately narrower than the vendored `generic-api-key` rule: this
#: one exists to catch what that rule's own allowlist filters out, tuned by
#: `[secrets] generic_entropy` rather than a fixed entropy cutoff.
_GENERIC_ASSIGNMENT_RE = re2.compile(
    r"(?i)[\w.-]{0,50}?(?:key|secret|token|passw(?:or)?d|pwd|credential|auth)"
    r"[\w.-]{0,20}\s*(?:=|:|=>)\s*['\"]?([A-Za-z0-9_+/=.-]{16,200})['\"]?"
)


def shannon_entropy(data: str) -> float:
    """Bits per symbol needed to encode `data`, gitleaks's own metric
    (https://github.com/gitleaks/gitleaks/blob/v8.30.1/detect/utils.go)."""
    if not data:
        return 0.0
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        freq = count / length
        entropy -= freq * math.log2(freq)
    return entropy


def _is_lockfile(path: str) -> bool:
    if not path:
        return False
    name = PurePosixPath(path).name
    return name in _LOCKFILE_NAMES or name.endswith(".lock")


def _line_col(text: str, offset: int) -> tuple[int, int]:
    """1-based (line, column) of `offset` within `text`."""
    prefix_end = offset
    line = text.count("\n", 0, prefix_end) + 1
    last_nl = text.rfind("\n", 0, prefix_end)
    return line, prefix_end - last_nl


def _line_at(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    return text[start:end]


@dataclass(slots=True)
class _RawFinding:
    """One content-level match: before path/commit-dependent filtering, the
    generic-overlap filter and the `Detection` conversion. `line_text` is computed
    once here (content-scan time) since `filter_occurrence` needs it for every
    occurrence but must never re-scan the text to get it.
    """

    rule_id: str
    start: int
    end: int
    value: str  # the secret, after secretGroup extraction (or the path, for a
    # path-only match)
    match: str  # the full trimmed regex match (used for allowlist regexTarget="match")
    line_no: int
    col: int
    line_text: str = ""


@dataclass(frozen=True, slots=True)
class ContentScan:
    """Every rule and generic-entropy candidate found in one blob/message/field's
    text, independent of any (path, commit) occurrence. Build once per unit of text
    with `SecretsEngine.scan_content()`; turn into `Detection`s for one concrete
    occurrence with `SecretsEngine.filter_occurrence()`.
    """

    candidates: tuple[_RawFinding, ...]


def _check_commit_or_path_allowed(ctx: UnitCtx, allowlists: tuple[Allowlist, ...]) -> bool:
    """Port of `checkCommitOrPathAllowed` (detect.go): a fragment-level (not
    finding-level) allowlist check on commit and path alone."""
    if not ctx.path and not ctx.commit:
        return False
    for allowlist in allowlists:
        commit_allowed = bool(ctx.commit) and ctx.commit.lower() in allowlist.commits
        path_allowed = bool(ctx.path) and any(p.search(ctx.path) for p in allowlist.paths)
        if allowlist.condition == "AND":
            checks = []
            if allowlist.commits:
                checks.append(commit_allowed)
            if allowlist.paths:
                checks.append(path_allowed)
            if allowlist.regexes or allowlist.stopwords:
                # Regex/stopword criteria need the finding; deferred to
                # `_check_finding_allowed`, exactly as gitleaks defers them.
                continue
            allowed = all(checks) if checks else True
        else:
            allowed = commit_allowed or path_allowed
        if allowed:
            return True
    return False


def _contains_stopword(value: str, stopwords: frozenset[str]) -> bool:
    if not stopwords or not value:
        return False
    lowered = value.lower()
    return any(word in lowered for word in stopwords)


def _check_finding_allowed(
    finding: _RawFinding, ctx: UnitCtx, line_text: str, allowlists: tuple[Allowlist, ...]
) -> bool:
    """Port of `checkFindingAllowed` (detect.go): regex/stopword/commit/path checks
    against one concrete finding."""
    for allowlist in allowlists:
        target = finding.value
        if allowlist.regex_target == "match":
            target = finding.match
        elif allowlist.regex_target == "line":
            target = line_text
        # gitleaks's `RegexAllowed` (allowlist.go) short-circuits to false on an
        # empty target regardless of whether the regex itself could match empty
        # (e.g. `.*`); `target` can be empty via a non-participating secretGroup.
        regex_allowed = (
            bool(allowlist.regexes)
            and bool(target)
            and any(p.search(target) for p in allowlist.regexes)
        )
        stopword_allowed = _contains_stopword(finding.value, allowlist.stopwords)
        if allowlist.condition == "AND":
            checks = []
            if allowlist.commits:
                checks.append(bool(ctx.commit) and ctx.commit.lower() in allowlist.commits)
            if allowlist.paths:
                checks.append(bool(ctx.path) and any(p.search(ctx.path) for p in allowlist.paths))
            if allowlist.regexes:
                checks.append(regex_allowed)
            if allowlist.stopwords:
                checks.append(stopword_allowed)
            allowed = all(checks) if checks else False
        else:
            allowed = regex_allowed or stopword_allowed
        if allowed:
            return True
    return False


def _within_proximity(primary: _RawFinding, required: _RawFinding, rule: Required) -> bool:
    """Port of `withinProximity` (detect.go)."""
    if rule.within_lines is None and rule.within_columns is None:
        return True
    line_gap = abs(primary.line_no - required.line_no)
    if rule.within_lines is not None and line_gap > rule.within_lines:
        return False
    col_gap = abs(primary.col - required.col)
    return not (rule.within_columns is not None and col_gap > rule.within_columns)


def _is_generic(rule_id: str) -> bool:
    return "generic" in rule_id.lower()


def _filter_generic_overlap(findings: list[_RawFinding]) -> list[_RawFinding]:
    """Port of `filter` (detect/utils.go): drop a generic finding covered by a more
    specific (non-generic) finding on the same line."""
    kept = []
    for f in findings:
        drop = False
        if _is_generic(f.rule_id) and f.value:
            for other in findings:
                if (
                    other.line_no == f.line_no
                    and other.rule_id != f.rule_id
                    and not _is_generic(other.rule_id)
                    and f.value in other.value
                ):
                    drop = True
                    break
        if not drop:
            kept.append(f)
    return kept


def _to_detection(raw: _RawFinding, *, path_only: bool) -> Detection:
    severity = "high" if _is_generic(raw.rule_id) else "critical"
    extra: dict[str, object] = {"path_match": True} if path_only else {}
    return Detection(
        category="secret",
        rule_id=raw.rule_id,
        severity=severity,
        start=raw.start,
        end=raw.end,
        line=raw.line_no,
        col=raw.col,
        value=raw.value,
        secret=True,
        extra=extra,
    )


class SecretsEngine:
    """Runs the vendored gitleaks rules plus the generic-entropy detector over one
    unit of text (a blob, a commit/tag message, a binary field).

    `scan_content()` does the content-only work exactly once; `filter_occurrence()`
    applies one `(path, commit)` occurrence's path/commit-dependent decisions to that
    result. `detect()` chains both for a single occurrence.
    """

    def __init__(
        self,
        config: GitleaksConfig,
        *,
        generic_entropy_threshold: float = 4.3,
        generic_detector_enabled: bool = True,
    ) -> None:
        self._config = config
        self._generic_threshold = generic_entropy_threshold
        self._generic_enabled = generic_detector_enabled

    def scan_content(self, text: str) -> ContentScan:
        """Keyword prefilter, regex match, `secretGroup` extraction, entropy gating
        and required-rule proximity: everything that depends only on `text`, run
        exactly once. Path-only rules (no regex to run) and every path/commit-
        dependent check are deferred entirely to `filter_occurrence`.
        """
        normalized = text.lower()
        candidates: list[_RawFinding] = []
        for rule in self._config.rules.values():
            if rule.regex is None or rule.skip_report:
                continue  # path-only, or never reported at the top level
            if not self._keyword_prefilter_passes(rule, normalized):
                continue
            primary = self._regex_matches(text, rule)
            if rule.required:
                primary = self._apply_required_content(text, rule, primary)
            candidates.extend(primary)

        if self._generic_enabled:
            candidates.extend(self._match_generic_entropy_content(text))

        return ContentScan(candidates=tuple(candidates))

    def filter_occurrence(self, scan: ContentScan, ctx: UnitCtx | None = None) -> list[Detection]:
        """Turn one blob/message's content-scan into `Detection`s for one concrete
        `(path, commit)` occurrence: the global allowlist gate, a rule's own `path`,
        per-rule and global allowlists, the generic-entropy lockfile skip, path-only
        rules, and the generic/specific overlap filter.
        """
        ctx = ctx or UnitCtx()
        if _check_commit_or_path_allowed(ctx, self._config.allowlists):
            return []

        kept: list[_RawFinding] = []
        path_only_ids: set[str] = set()

        for finding in scan.candidates:
            if finding.rule_id == "generic-entropy":
                if _is_lockfile(ctx.path):
                    continue
                if _check_finding_allowed(finding, ctx, finding.line_text, self._config.allowlists):
                    continue
                kept.append(finding)
                continue

            rule = self._config.rules.get(finding.rule_id)
            if rule is None:
                continue  # defensive: config changed between scan and filter
            if _check_commit_or_path_allowed(ctx, rule.allowlists):
                continue
            if rule.path is not None and not rule.path.search(ctx.path):
                continue
            if _check_finding_allowed(finding, ctx, finding.line_text, self._config.allowlists):
                continue
            if _check_finding_allowed(finding, ctx, finding.line_text, rule.allowlists):
                continue
            kept.append(finding)

        for rule in self._config.rules.values():
            if rule.regex is not None or rule.path is None or rule.skip_report:
                continue  # not a (reported) path-only rule
            if _check_commit_or_path_allowed(ctx, rule.allowlists):
                continue
            if not rule.path.search(ctx.path):
                continue
            kept.append(
                _RawFinding(
                    rule_id=rule.id,
                    start=0,
                    end=0,
                    value=ctx.path,
                    match=ctx.path,
                    line_no=0,
                    col=0,
                )
            )
            path_only_ids.add(rule.id)

        kept = _filter_generic_overlap(kept)
        return [_to_detection(f, path_only=f.rule_id in path_only_ids) for f in kept]

    def detect(self, text: str, ctx: UnitCtx | None = None) -> list[Detection]:
        """Convenience for a single text/occurrence pair (unit tests, and any caller
        that only ever sees one occurrence): `scan_content` then `filter_occurrence`.
        `scan.py` calls them separately to scan a blob's content once and reuse it
        across every occurrence.
        """
        return self.filter_occurrence(self.scan_content(text), ctx)

    @staticmethod
    def _keyword_prefilter_passes(rule: Rule, normalized_text: str) -> bool:
        if not rule.keywords:
            return True
        return any(keyword in normalized_text for keyword in rule.keywords)

    def _regex_matches(self, raw_text: str, rule: Rule) -> list[_RawFinding]:
        """Content-only regex/secretGroup/entropy matching for one rule (no `path`
        or allowlist checks: those are per-occurrence, in `filter_occurrence`)."""
        assert rule.regex is not None
        findings: list[_RawFinding] = []
        for m in rule.regex.finditer(raw_text):
            match_text = m.group(0).strip("\n")
            start = m.start()
            end = start + len(match_text)

            value = match_text
            if rule.regex.groups > 0:
                resub = rule.regex.search(match_text)
                if resub is not None:
                    if rule.secret_group > 0:
                        if rule.secret_group > rule.regex.groups:
                            continue  # load-time validation should prevent this
                        # A non-participating optional group is `""` in Go's
                        # `FindStringSubmatch` (never absent) so gitleaks still
                        # emits a finding with an empty secret; re2's Python binding
                        # returns `None` here instead of `""`, so translate it to
                        # match rather than dropping the finding.
                        candidate = resub.group(rule.secret_group)
                        value = candidate if candidate is not None else ""
                    else:
                        for i in range(1, rule.regex.groups + 1):
                            candidate = resub.group(i)
                            if candidate:
                                value = candidate
                                break

            entropy = shannon_entropy(value)
            if rule.entropy != 0.0 and entropy <= rule.entropy:
                continue

            line_no, col = _line_col(raw_text, start)
            findings.append(
                _RawFinding(
                    rule_id=rule.id,
                    start=start,
                    end=end,
                    value=value,
                    match=match_text,
                    line_no=line_no,
                    col=col,
                    line_text=_line_at(raw_text, start),
                )
            )
        return findings

    def _apply_required_content(
        self, raw_text: str, rule: Rule, primary: list[_RawFinding]
    ) -> list[_RawFinding]:
        """Content-only port of `withinProximity`/`processRequiredRules`: no rule in
        the bundled config combines `required` with a `path` filter (see the module
        docstring), so both the primary and required sub-rule matches are gathered
        ignoring `path` here; the primary rule's own `path` is still applied per
        occurrence afterwards.
        """
        if not primary:
            return primary

        per_required: dict[str, list[_RawFinding]] = {}
        for req in rule.required:
            sub_rule = self._config.rules.get(req.rule_id)
            if sub_rule is None or sub_rule.regex is None:
                continue
            per_required[req.rule_id] = self._regex_matches(raw_text, sub_rule)

        required_ids = {req.rule_id for req in rule.required}
        final: list[_RawFinding] = []
        for pf in primary:
            matched_ids: set[str] = set()
            for req in rule.required:
                for candidate in per_required.get(req.rule_id, []):
                    if _within_proximity(pf, candidate, req):
                        matched_ids.add(req.rule_id)
                        break
            if matched_ids == required_ids:
                final.append(pf)
        return final

    def _match_generic_entropy_content(self, text: str) -> list[_RawFinding]:
        """Content-only generic-entropy candidates; the lockfile skip and the global
        allowlist are per-occurrence (`filter_occurrence`)."""
        findings: list[_RawFinding] = []
        offset = 0
        for line_text in text.split("\n"):
            line_start = offset
            offset += len(line_text) + 1
            if len(line_text) > _MAX_GENERIC_LINE_CHARS:
                continue
            for m in _GENERIC_ASSIGNMENT_RE.finditer(line_text):
                value = m.group(1)
                if not value:
                    continue
                if shannon_entropy(value) < self._generic_threshold:
                    continue
                start = line_start + m.start(1)
                end = start + len(value)
                line_no, col = _line_col(text, start)
                findings.append(
                    _RawFinding(
                        rule_id="generic-entropy",
                        start=start,
                        end=end,
                        value=value,
                        match=value,
                        line_no=line_no,
                        col=col,
                        line_text=line_text,
                    )
                )
        return findings
