"""The pydantic `Config` model (architecture.md "Config"), `extra="forbid"` at every
level so an unknown key is a `ConfigError` (exit 2).

Stage 2b ships every table the architecture names, with its defaults, and only the
minimal discovery the stage-2 brief asks for: an explicit `--config` path, or the
built-in defaults. `$GO_PUBLIC_CONFIG`, the XDG file and the tracked `.go-public.toml`
(read from the export ref's tree) are stage 4's `config.py` completion.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from go_public.detect.constants import DEFAULT_ALLOWED_PATH_PREFIXES, DEFAULT_INTERNAL_SUFFIXES
from go_public.errors import ConfigError

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
    generic_entropy: float = 4.3  # tuned on seeds 0-1 only, stage 6
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
    `.go-public.toml`) is stage 4's job; the CLI passes `--config` straight through.
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
