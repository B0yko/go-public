"""The pydantic `Config` model, `extra="forbid"` at every level so an unknown key is
a `ConfigError` (exit 2).

`load_config` reads an explicit `--config` path or returns the built-in defaults.
`discover_config` adds `$GO_PUBLIC_CONFIG`, the XDG file and the tracked
`.go-public.toml` (read from the export ref's tree).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from go_public.detect.constants import DEFAULT_ALLOWED_PATH_PREFIXES, DEFAULT_INTERNAL_SUFFIXES
from go_public.errors import ConfigError, GitError
from go_public.git.runner import GitRunner
from go_public.model import repo_display_name

_DEFAULT_SENSITIVE_FILES = (
    "id_rsa*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    ".env",
    ".env.*",
    "!.env.example",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "*.kdbx",
    "*.har",
    "*.sql",
    "*.sqlite",
    "*.db",
    ".DS_Store",
    ".idea/workspace.xml",
)
_DEFAULT_INTERNAL_NOTES = (
    "NOTES*.md",
    "notes/**",
    "scratch/**",
    "drafts/**",
    "*.draft.md",
    "internal/**",
    "INTERNAL*",
    "*.private.*",
)
_DEFAULT_TRAILERS_FLAG = (
    "Co-authored-by",
    "Signed-off-by",
    "Reviewed-by",
    "Reported-by",
    "Acked-by",
    "Change-Id",
    "Cc",
)


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RepoConfig(_Base):
    path: str = ""


class IdentityConfig(_Base):
    allow: list[str] = Field(default_factory=list)


class DenyConfig(_Base):
    terms: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    regex: list[str] = Field(default_factory=list)
    names: list[str] = Field(default_factory=list)
    ticket_keys: list[str] = Field(default_factory=list)


class SecretsConfig(_Base):
    gitleaks_config: str = ""  # empty = bundled rules
    generic_entropy: float = 4.0  # tuned on seeds 0-1 only; see docs/adr/0010
    generic_detector: bool = True


class PiiConfig(_Base):
    phone_regions: list[str] = Field(default_factory=lambda: ["US", "GB", "DE"])
    detect_names: bool = False


class PathsConfig(_Base):
    allowed_prefixes: list[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_PATH_PREFIXES))


class NetworkConfig(_Base):
    internal_suffixes: list[str] = Field(default_factory=lambda: list(DEFAULT_INTERNAL_SUFFIXES))


class LicenceConfig(_Base):
    owner: str = ""


class ScanConfig(_Base):
    max_scan_mb: int = 10
    jobs: int = 0  # 0 = CPU count
    fail_on: str = "high"


class FilesConfig(_Base):
    sensitive_files: list[str] = Field(default_factory=lambda: list(_DEFAULT_SENSITIVE_FILES))
    internal_notes: list[str] = Field(default_factory=lambda: list(_DEFAULT_INTERNAL_NOTES))
    warn_mb: int = 5
    high_mb: int = 50
    auto_exclude: bool = True


class TrailersConfig(_Base):
    flag: list[str] = Field(default_factory=lambda: list(_DEFAULT_TRAILERS_FLAG))


class FingerprintEntry(_Base):
    id: str
    reason: str


class AllowlistConfig(_Base):
    paths: list[str] = Field(default_factory=list)
    fingerprints: list[FingerprintEntry] = Field(default_factory=list)


class RotatedConfig(_Base):
    fingerprints: list[FingerprintEntry] = Field(default_factory=list)


class ExportConfig(_Base):
    author: str = ""
    message: str = "Initial public release"
    date: str = "now"
    exclude: list[str] = Field(default_factory=list)
    strip_metadata: bool = True


class Config(_Base):
    repo: RepoConfig = Field(default_factory=RepoConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    deny: DenyConfig = Field(default_factory=DenyConfig)
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    pii: PiiConfig = Field(default_factory=PiiConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    licence: LicenceConfig = Field(default_factory=LicenceConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    files: FilesConfig = Field(default_factory=FilesConfig)
    trailers: TrailersConfig = Field(default_factory=TrailersConfig)
    allowlist: AllowlistConfig = Field(default_factory=AllowlistConfig)
    rotated: RotatedConfig = Field(default_factory=RotatedConfig)
    export: ExportConfig = Field(default_factory=ExportConfig)


def load_config(path: str | Path | None = None) -> Config:
    """Load `path` (a TOML file) or return the defaults when `path is None`.

    Discovery beyond an explicit path (`$GO_PUBLIC_CONFIG`, the XDG file, the tracked
    `.go-public.toml`) lives in `discover_config`.
    """
    if path is None:
        return Config()
    text_path = Path(path)
    try:
        data = tomllib.loads(text_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config {text_path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in config {text_path}: {exc}") from exc
    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid config {text_path}: {exc}") from exc


# -- discovery: --config > $GO_PUBLIC_CONFIG > XDG file > tracked --------------------


def xdg_config_path(repo: Path) -> Path:
    """`$XDG_CONFIG_HOME/go-public/<repo-dir-name>.toml` (`$XDG_CONFIG_HOME` default
    `~/.config`) — where `go-public init` writes and discovery's third step reads."""
    xdg_home = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg_home) if xdg_home else Path.home() / ".config"
    return base / "go-public" / f"{repo_display_name(str(repo))}.toml"


def _read_tracked_config_text(runner: GitRunner, ref: str) -> str | None:
    """`.go-public.toml` at `ref`'s tree, or `None` when the repo has none there.
    Uses `cat-file -p <ref>:<path>`, a single read-only call any `source`-role runner
    already allows."""
    try:
        content = runner.run(["cat-file", "-p", f"{ref}:.go-public.toml"])
    except GitError:
        return None
    return content.decode("utf-8", errors="replace")


def _tracked_allowlist_config(text: str) -> Config:
    """Only `[allowlist]` and `[identity].allow` are read from a *tracked* config
    (the discovery order allows a tracked `.go-public.toml` for allowlists only; the
    identity allowlist only removes findings, so it counts); every other
    table a committed file might carry is ignored here (`detect/files.py`'s
    `check_tracked_config`/`scan.py`'s `_scan_tracked_config` separately flag a
    non-empty `[deny]` table there as a critical finding, so this never silently lets
    a committed repo widen its own scan)."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return Config()
    allowlist_data = data.get("allowlist")
    identity_data = data.get("identity")
    try:
        return Config(
            allowlist=(
                AllowlistConfig.model_validate(allowlist_data)
                if isinstance(allowlist_data, dict)
                else AllowlistConfig()
            ),
            # `[identity].allow` is an allowlist too (it only removes findings).
            identity=(
                IdentityConfig(allow=identity_data["allow"])
                if isinstance(identity_data, dict) and "allow" in identity_data
                else IdentityConfig()
            ),
        )
    except (ValidationError, TypeError):
        return Config()


@dataclass(frozen=True, slots=True)
class ConfigDiscovery:
    config: Config
    source: str
    warnings: list[str] = field(default_factory=list)


def discover_config(
    *,
    explicit: str | Path | None,
    repo: Path,
    runner: GitRunner | None = None,
    export_ref: str = "HEAD",
) -> ConfigDiscovery:
    """Resolve go-public's config: `--config` (`explicit`) wins outright; else
    `$GO_PUBLIC_CONFIG`; else the XDG file (ignored with a warning when its own
    `[repo] path` names a different repository); else a tracked `.go-public.toml` at
    `export_ref` (allowlists only, read through `runner` when given); else the
    built-in defaults. `source` is a short description for
    `Report.scan.options.config_source`."""
    if explicit is not None:
        return ConfigDiscovery(config=load_config(explicit), source=str(explicit))

    env_path = os.environ.get("GO_PUBLIC_CONFIG")
    if env_path:
        return ConfigDiscovery(config=load_config(env_path), source=f"env:{env_path}")

    warnings: list[str] = []
    xdg_path = xdg_config_path(repo)
    if xdg_path.is_file():
        candidate = load_config(xdg_path)
        configured_path = candidate.repo.path.strip()
        if configured_path and Path(configured_path).resolve() != repo.resolve():
            warnings.append(
                f"ignoring {xdg_path}: [repo] path {configured_path!r} names a different repository"
            )
        else:
            return ConfigDiscovery(config=candidate, source=str(xdg_path), warnings=warnings)

    if runner is not None:
        text = _read_tracked_config_text(runner, export_ref)
        if text is not None:
            return ConfigDiscovery(
                config=_tracked_allowlist_config(text),
                source=f".go-public.toml@{export_ref}",
                warnings=warnings,
            )

    return ConfigDiscovery(config=Config(), source="defaults", warnings=warnings)
