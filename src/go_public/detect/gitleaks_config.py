"""Load and validate a gitleaks-format TOML config (own or `--gitleaks-config`).

A from-scratch Python port of the parts of gitleaks v8.30.1's `config` package that
matter for detection: `config/config.go` (`ViperConfig.Translate`, `extend*`),
`config/rule.go` (`Rule.Validate`), `config/allowlist.go` (`Allowlist.Validate`).
See docs/adr/0002-re2-and-ported-gitleaks-semantics.md.

Two deliberate departures from gitleaks itself, both because go-public's config
handling is stricter by design (architecture.md, product spec item 2):
- Any key gitleaks's viper unmarshalling would silently ignore is a `ConfigError`
  (exit 2) here instead.
- A pattern that fails to compile does not abort loading; it is recorded in
  `GitleaksConfig.compile_failures` so `go-public rules check` can name every
  failure in one run instead of stopping at the first. A rule whose only pattern
  fails to compile behaves as if that pattern were absent (skips those matches);
  a genuinely empty rule (`regex` and `path` both absent) is still a `ConfigError`.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from importlib import resources
from pathlib import Path
from typing import Any

import re2

from go_public.errors import ConfigError

#: The gitleaks release this port matches. `minVersion` newer than this warns.
PINNED_GITLEAKS_VERSION = (8, 30, 1)

_MAX_EXTEND_DEPTH = 2

_TOP_KEYS = {"title", "description", "extend", "rules", "allowlist", "allowlists", "minversion"}
_EXTEND_KEYS = {"path", "url", "usedefault", "disabledrules"}
_RULE_KEYS = {
    "id",
    "description",
    "path",
    "regex",
    "secretgroup",
    "entropy",
    "keywords",
    "tags",
    "allowlist",
    "allowlists",
    "required",
    "skipreport",
}
_ALLOWLIST_KEYS = {
    "description",
    "condition",
    "commits",
    "paths",
    "regextarget",
    "regexes",
    "stopwords",
}
_TARGET_RULES_KEY = "targetrules"
_REQUIRED_KEYS = {"id", "withinlines", "withincolumns"}


@dataclass(frozen=True, slots=True)
class Required:
    """One `[[rules.required]]` entry: a composite rule's dependency on another rule."""

    rule_id: str
    within_lines: int | None = None
    within_columns: int | None = None


@dataclass(frozen=True, slots=True)
class Allowlist:
    """A parsed `[allowlist]` / `[[allowlists]]` / `[[rules.allowlists]]` entry.

    `condition` is `"OR"` (default) or `"AND"`. `regex_target` is `""` (the secret,
    gitleaks's default), `"match"` (the whole rule match) or `"line"`.
    """

    description: str = ""
    condition: str = "OR"
    commits: frozenset[str] = field(default_factory=frozenset)
    paths: tuple[Any, ...] = ()
    regex_target: str = ""
    regexes: tuple[Any, ...] = ()
    stopwords: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class Rule:
    """One `[[rules]]` entry, compiled. `regex is None` means a path-only rule."""

    id: str
    description: str = ""
    regex: Any | None = None
    secret_group: int = 0
    entropy: float = 0.0
    keywords: tuple[str, ...] = ()
    path: Any | None = None
    tags: tuple[str, ...] = ()
    allowlists: tuple[Allowlist, ...] = ()
    required: tuple[Required, ...] = ()
    skip_report: bool = False


@dataclass(frozen=True, slots=True)
class CompileFailure:
    """A pattern that did not compile under `re2`; named by `rules check`."""

    context: str
    pattern: str
    message: str


@dataclass(frozen=True, slots=True)
class GitleaksConfig:
    """A fully loaded (and, if `[extend]` was set, merged) gitleaks-format config."""

    title: str = ""
    description: str = ""
    min_version: str = ""
    rules: dict[str, Rule] = field(default_factory=dict)
    allowlists: tuple[Allowlist, ...] = ()
    keywords: frozenset[str] = field(default_factory=frozenset)
    warnings: tuple[str, ...] = ()
    compile_failures: tuple[CompileFailure, ...] = ()


@dataclass(frozen=True, slots=True)
class _ExtendSpec:
    path: str = ""
    url: str = ""
    use_default: bool = False
    disabled_rules: tuple[str, ...] = ()


def _norm(table: Mapping[str, Any]) -> dict[str, Any]:
    return {str(k).lower(): v for k, v in table.items()}


def _check_keys(norm: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(norm) - allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(unknown)}")


def _compile(pattern: object, *, context: str, failures: list[CompileFailure]) -> Any | None:
    if not isinstance(pattern, str):
        raise ConfigError(f"{context}: expected a string pattern, got {type(pattern).__name__}")
    try:
        return re2.compile(pattern)
    except re2.error as exc:
        failures.append(CompileFailure(context=context, pattern=pattern, message=str(exc)))
        return None


def _parse_semver(text: str) -> tuple[int, ...] | None:
    text = text.strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    parts = text.split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def _parse_extend(raw: Any) -> _ExtendSpec:
    if raw is None:
        return _ExtendSpec()
    if not isinstance(raw, dict):
        raise ConfigError("[extend]: expected a table")
    norm = _norm(raw)
    _check_keys(norm, _EXTEND_KEYS, "[extend]")
    path = str(norm.get("path") or "")
    url = str(norm.get("url") or "")
    use_default = bool(norm.get("usedefault", False))
    disabled = tuple(str(x) for x in (norm.get("disabledrules") or []))
    if path and use_default:
        raise ConfigError("[extend]: path and useDefault cannot both be set")
    return _ExtendSpec(path=path, url=url, use_default=use_default, disabled_rules=disabled)


def _collect_allowlist_tables(norm: dict[str, Any], *, where: str) -> list[dict[str, Any]]:
    singular = norm.get("allowlist")
    plural = norm.get("allowlists")
    if singular is not None and plural:
        raise ConfigError(
            f"{where}: [allowlist] is deprecated, it cannot be used alongside [[allowlists]]"
        )
    if singular is not None:
        if not isinstance(singular, dict):
            raise ConfigError(f"{where}: [allowlist] must be a table")
        return [singular]
    if plural:
        if not isinstance(plural, list):
            raise ConfigError(f"{where}: [[allowlists]] must be an array of tables")
        return list(plural)
    return []


def _parse_allowlist_table(
    raw: Any, *, allow_target_rules: bool, where: str, failures: list[CompileFailure]
) -> tuple[Allowlist, tuple[str, ...]]:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected a table")
    norm = _norm(raw)
    allowed = _ALLOWLIST_KEYS | ({_TARGET_RULES_KEY} if allow_target_rules else set())
    _check_keys(norm, allowed, where)

    condition_raw = str(norm.get("condition") or "").upper()
    if condition_raw in ("", "OR", "||"):
        condition = "OR"
    elif condition_raw in ("AND", "&&"):
        condition = "AND"
    else:
        raise ConfigError(f"{where}: unknown condition {condition_raw!r} (expected 'and'/'or')")

    regex_target_raw = str(norm.get("regextarget") or "")
    if regex_target_raw == "secret":
        regex_target = ""
    elif regex_target_raw in ("", "match", "line"):
        regex_target = regex_target_raw
    else:
        raise ConfigError(
            f"{where}: unknown regexTarget {regex_target_raw!r} (expected 'match'/'line')"
        )

    raw_commits = norm.get("commits") or []
    raw_paths = norm.get("paths") or []
    raw_regexes = norm.get("regexes") or []
    raw_stopwords = norm.get("stopwords") or []
    if not (raw_commits or raw_paths or raw_regexes or raw_stopwords):
        raise ConfigError(
            f"{where}: must contain at least one check for commits, paths, regexes, or stopwords"
        )

    commits = frozenset(str(c).strip().lower() for c in raw_commits)
    paths = tuple(
        p
        for p in (_compile(rp, context=f"{where}: path", failures=failures) for rp in raw_paths)
        if p is not None
    )
    regexes = tuple(
        p
        for p in (_compile(rp, context=f"{where}: regex", failures=failures) for rp in raw_regexes)
        if p is not None
    )
    stopwords = frozenset(str(s).lower() for s in raw_stopwords)

    target_rules = (
        tuple(str(t) for t in (norm.get(_TARGET_RULES_KEY) or [])) if allow_target_rules else ()
    )

    allowlist = Allowlist(
        description=str(norm.get("description") or ""),
        condition=condition,
        commits=commits,
        paths=paths,
        regex_target=regex_target,
        regexes=regexes,
        stopwords=stopwords,
    )
    return allowlist, target_rules


def _parse_required(raw: Any, *, index: int, rule_id: str) -> Required:
    if not isinstance(raw, dict):
        raise ConfigError(f"rule {rule_id}: [[required]] entry {index}: expected a table")
    norm = _norm(raw)
    _check_keys(norm, _REQUIRED_KEYS, f"rule {rule_id}: [[required]] entry {index}")
    req_id = str(norm.get("id") or "").strip()
    if not req_id:
        raise ConfigError(f"rule {rule_id}: [[required]] entry {index}: |id| is missing or empty")
    within_lines = norm.get("withinlines")
    within_columns = norm.get("withincolumns")
    return Required(
        rule_id=req_id,
        within_lines=int(within_lines) if within_lines is not None else None,
        within_columns=int(within_columns) if within_columns is not None else None,
    )


def _parse_rule(raw: Any, *, index: int, failures: list[CompileFailure]) -> Rule:
    if not isinstance(raw, dict):
        raise ConfigError(f"[[rules]] entry {index}: expected a table")
    norm = _norm(raw)
    _check_keys(norm, _RULE_KEYS, f"[[rules]] entry {index}")

    rule_id = str(norm.get("id") or "").strip()
    if not rule_id:
        raise ConfigError(f"[[rules]] entry {index}: |id| is missing or empty")

    # `regex`/`path` completeness and `secretGroup` range are validated once, after
    # `[extend]` has merged (see `_validate_final`): an overlay rule that only
    # overrides a scalar field (e.g. `entropy`) and relies on the base for its
    # actual `regex` is valid on its own, exactly as gitleaks defers
    # `Rule.Validate()` to the fully-assembled config.
    regex_src = norm.get("regex")
    path_src = norm.get("path")
    regex = None
    if regex_src:
        regex = _compile(regex_src, context=f"rule {rule_id}: regex", failures=failures)
    path = None
    if path_src:
        path = _compile(path_src, context=f"rule {rule_id}: path", failures=failures)

    secret_group = int(norm.get("secretgroup") or 0)

    keywords = tuple(sorted({str(k).lower() for k in (norm.get("keywords") or [])}))
    tags = tuple(str(t) for t in (norm.get("tags") or []))
    skip_report = bool(norm.get("skipreport", False))

    allowlists = []
    for table in _collect_allowlist_tables(norm, where=f"rule {rule_id}"):
        allowlist, target_rules = _parse_allowlist_table(
            table, allow_target_rules=False, where=f"rule {rule_id}: allowlist", failures=failures
        )
        if target_rules:
            raise ConfigError(f"rule {rule_id}: allowlist: targetRules is only valid at top level")
        allowlists.append(allowlist)

    required = [
        _parse_required(raw_req, index=i, rule_id=rule_id)
        for i, raw_req in enumerate(norm.get("required") or [])
    ]

    return Rule(
        id=rule_id,
        description=str(norm.get("description") or ""),
        regex=regex,
        secret_group=secret_group,
        entropy=float(norm.get("entropy") or 0.0),
        keywords=keywords,
        path=path,
        tags=tags,
        allowlists=tuple(allowlists),
        required=tuple(required),
        skip_report=skip_report,
    )


def _translate(data: dict[str, Any]) -> tuple[GitleaksConfig, _ExtendSpec]:
    norm = _norm(data)
    _check_keys(norm, _TOP_KEYS, "config")

    min_version = str(norm.get("minversion") or "")
    extend_spec = _parse_extend(norm.get("extend"))

    failures: list[CompileFailure] = []
    rules: dict[str, Rule] = {}
    keywords: set[str] = set()
    for i, raw_rule in enumerate(norm.get("rules") or []):
        rule = _parse_rule(raw_rule, index=i, failures=failures)
        if rule.id in rules:
            raise ConfigError(f"duplicate rule id {rule.id!r}")
        rules[rule.id] = rule
        keywords.update(rule.keywords)

    # Ported from `Translate()` (config.go): required-rule references are checked
    # against this same file's own rule set, before `[extend]` merges anything in.
    for rule in rules.values():
        for req in rule.required:
            if req.rule_id not in rules:
                raise ConfigError(
                    f"{rule.id}: [[rules.required]] rule ID '{req.rule_id}' does not exist"
                )

    plain_allowlists: list[Allowlist] = []
    for table in _collect_allowlist_tables(norm, where="config"):
        allowlist, target_rules = _parse_allowlist_table(
            table, allow_target_rules=True, where="[allowlist]/[[allowlists]]", failures=failures
        )
        if target_rules:
            for rule_id in target_rules:
                if rule_id not in rules:
                    raise ConfigError(f"[[allowlists]] target rule ID {rule_id!r} does not exist")
                existing = rules[rule_id]
                rules[rule_id] = replace(existing, allowlists=existing.allowlists + (allowlist,))
        else:
            plain_allowlists.append(allowlist)

    warnings = []
    parsed_version = _parse_semver(min_version) if min_version else None
    if parsed_version is not None and parsed_version > PINNED_GITLEAKS_VERSION:
        pinned = ".".join(str(p) for p in PINNED_GITLEAKS_VERSION)
        warnings.append(f"config requires gitleaks {min_version}, newer than the pinned v{pinned}")

    cfg = GitleaksConfig(
        title=str(norm.get("title") or ""),
        description=str(norm.get("description") or ""),
        min_version=min_version,
        rules=rules,
        allowlists=tuple(plain_allowlists),
        keywords=frozenset(keywords),
        warnings=tuple(warnings),
        compile_failures=tuple(failures),
    )
    return cfg, extend_spec


def _merge(
    base: GitleaksConfig, top: GitleaksConfig, disabled_rule_ids: frozenset[str]
) -> GitleaksConfig:
    """Merge `top` (the config with `[extend]`) over `base` (what it extends).

    Ports `Config.extend` (config/config.go): rules only in `base` are added as-is;
    rules in both keep `top`'s non-empty scalar fields and the concatenation of
    `base`'s and `top`'s list fields (tags, keywords, allowlists).
    """
    merged_rules = dict(top.rules)
    keywords = set(top.keywords)
    for rule_id, base_rule in base.rules.items():
        if rule_id in disabled_rule_ids:
            continue
        current = merged_rules.get(rule_id)
        if current is None:
            merged_rules[rule_id] = base_rule
            keywords.update(base_rule.keywords)
            continue
        merged = Rule(
            id=rule_id,
            description=current.description or base_rule.description,
            regex=current.regex if current.regex is not None else base_rule.regex,
            secret_group=current.secret_group or base_rule.secret_group,
            entropy=current.entropy or base_rule.entropy,
            keywords=tuple(dict.fromkeys((*base_rule.keywords, *current.keywords))),
            path=current.path if current.path is not None else base_rule.path,
            tags=tuple(dict.fromkeys((*base_rule.tags, *current.tags))),
            allowlists=base_rule.allowlists + current.allowlists,
            required=current.required or base_rule.required,
            skip_report=current.skip_report or base_rule.skip_report,
        )
        merged_rules[rule_id] = merged
        keywords.update(merged.keywords)
    return GitleaksConfig(
        title=top.title,
        description=top.description,
        min_version=top.min_version,
        rules=merged_rules,
        allowlists=top.allowlists + base.allowlists,
        keywords=frozenset(keywords),
        warnings=top.warnings + base.warnings,
        compile_failures=top.compile_failures + base.compile_failures,
    )


def _bundled_text() -> str:
    return resources.files("go_public.rules").joinpath("gitleaks.toml").read_text(encoding="utf-8")


def _load_one(path: str | Path | None, *, depth: int) -> GitleaksConfig:
    if path is None:
        text = _bundled_text()
        source_dir: Path | None = None
    else:
        source_path = Path(path)
        try:
            text = source_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read gitleaks config {source_path}: {exc}") from exc
        source_dir = source_path.parent

    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in gitleaks config: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("gitleaks config must be a TOML table")

    cfg, extend_spec = _translate(data)

    if depth < _MAX_EXTEND_DEPTH:
        disabled = frozenset(extend_spec.disabled_rules)
        if extend_spec.use_default:
            base = _load_one(None, depth=depth + 1)
            cfg = _merge(base, cfg, disabled)
        elif extend_spec.path:
            if source_dir is None:
                raise ConfigError(
                    "[extend].path is relative to the extending file, but the bundled "
                    "config has no file path to resolve it against"
                )
            base = _load_one(source_dir / extend_spec.path, depth=depth + 1)
            cfg = _merge(base, cfg, disabled)
    return cfg


def _validate_final(config: GitleaksConfig) -> None:
    """Ported from `Rule.Validate()` (rule.go), run once on the fully assembled
    (post-`[extend]`) config, exactly as gitleaks defers it to `currentExtendDepth
    == 0`: an overlay rule that only overrides a scalar field is fine on its own,
    but the *merged* rule must still end up with a `regex` or a `path`, and a
    `secretGroup` still has to be a real capturing group of the final `regex`.
    """
    for rule in config.rules.values():
        if rule.regex is None and rule.path is None:
            raise ConfigError(
                f"{rule.id}: both |regex| and |path| are empty, this rule will have no effect"
            )
        if rule.regex is not None and rule.secret_group > rule.regex.groups:
            raise ConfigError(
                f"{rule.id}: invalid regex secret group {rule.secret_group}, "
                f"max regex secret group {rule.regex.groups}"
            )


def load_gitleaks_config(path: str | Path | None = None) -> GitleaksConfig:
    """Load and validate a gitleaks-format config. `path=None` loads the bundled
    v8.30.1 rule set (`src/go_public/rules/gitleaks.toml`) via `importlib.resources`.
    """
    config = _load_one(path, depth=0)
    _validate_final(config)
    return config


@dataclass(frozen=True, slots=True)
class RulesCheckResult:
    rule_count: int
    content_rule_count: int
    path_only_rule_count: int
    allowlist_regex_count: int
    failures: tuple[CompileFailure, ...]

    def summary_line(self) -> str:
        return (
            f"{self.rule_count} rules: {self.content_rule_count} content regexes, "
            f"{self.path_only_rule_count} path-only; "
            f"{self.allowlist_regex_count} allowlist regexes compiled"
        )


def rules_check(config: GitleaksConfig) -> RulesCheckResult:
    """Count rules and allowlist regexes the way `go-public rules check` reports them."""
    content = sum(1 for r in config.rules.values() if r.regex is not None)
    path_only = sum(1 for r in config.rules.values() if r.regex is None and r.path is not None)
    allowlist_regexes = sum(len(a.regexes) for a in config.allowlists)
    allowlist_regexes += sum(len(a.regexes) for r in config.rules.values() for a in r.allowlists)
    return RulesCheckResult(
        rule_count=len(config.rules),
        content_rule_count=content,
        path_only_rule_count=path_only,
        allowlist_regex_count=allowlist_regexes,
        failures=config.compile_failures,
    )
