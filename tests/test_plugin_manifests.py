"""Plugin manifests: version agreement, and validation against a schema written from the
documented fields (plugin manifest reference and marketplace reference, checked
2026-09-28). The official validator is run by hand; this keeps the same contract in CI."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from typer.testing import CliRunner

import go_public
from go_public.cli import app

ROOT = Path(__file__).resolve().parent.parent
PLUGIN_JSON = ROOT / ".claude-plugin" / "plugin.json"
MARKETPLACE_JSON = ROOT / ".claude-plugin" / "marketplace.json"

KEBAB = r"^[a-z0-9]+(-[a-z0-9]+)*$"
AUTHOR = {
    "type": "object",
    "required": ["name"],
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "email": {"type": "string"},
        "url": {"type": "string"},
    },
    "additionalProperties": False,
}

# Documented top-level fields of plugin.json; `name` is the only required one.
PLUGIN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["name"],
    "properties": {
        "$schema": {"type": "string"},
        "name": {"type": "string", "pattern": KEBAB},
        "displayName": {"type": "string"},
        "version": {"type": "string", "minLength": 1},
        "description": {"type": "string", "minLength": 1},
        "author": AUTHOR,
        "homepage": {"type": "string", "pattern": r"^https?://\S+$"},
        "repository": {"type": "string"},
        "license": {"type": "string"},
        "keywords": {"type": "array", "items": {"type": "string"}},
        "metadata": {"type": "object"},
        "defaultEnabled": {"type": "boolean"},
        "dependencies": {},
        "settings": {"type": "object"},
        "userConfig": {"type": "object"},
        "channels": {},
        "skills": {},
        "commands": {},
        "agents": {},
        "hooks": {},
        "mcpServers": {},
        "lspServers": {},
        "outputStyles": {},
        "workflows": {},
        "experimental": {"type": "object"},
    },
    "additionalProperties": False,
}

_SOURCE_STRING = {"type": "string", "pattern": r"^(\.|\./\S*)$"}
_SOURCE_OBJECT = {
    "type": "object",
    "required": ["source"],
    "properties": {"source": {"type": "string"}},
}

# Documented marketplace.json: `name`, `owner`, `plugins` required; each plugin entry needs
# `name` and `source`. Plugin entries also accept any plugin.json field.
MARKETPLACE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["name", "owner", "plugins"],
    "properties": {
        "$schema": {"type": "string"},
        "name": {"type": "string", "pattern": KEBAB},
        "owner": AUTHOR,
        "description": {"type": "string"},
        "version": {"type": "string"},
        "metadata": {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "version": {"type": "string"},
                "pluginRoot": {"type": "string"},
            },
        },
        "forceRemoveDeletedPlugins": {"type": "boolean"},
        "allowCrossMarketplaceDependenciesOn": {"type": "array"},
        "renames": {"type": "object"},
        "plugins": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["name", "source"],
                "properties": {
                    "name": {"type": "string", "pattern": KEBAB},
                    "source": {"oneOf": [_SOURCE_STRING, _SOURCE_OBJECT]},
                    "description": {"type": "string"},
                    "version": {"type": "string"},
                    "category": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "strict": {"type": "boolean"},
                    "author": AUTHOR,
                    "homepage": {"type": "string"},
                    "repository": {"type": "string"},
                    "license": {"type": "string"},
                    "keywords": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    },
    "additionalProperties": False,
}


def _load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_plugin_json_matches_the_documented_schema() -> None:
    jsonschema.validate(_load(PLUGIN_JSON), PLUGIN_SCHEMA)


def test_marketplace_json_matches_the_documented_schema() -> None:
    jsonschema.validate(_load(MARKETPLACE_JSON), MARKETPLACE_SCHEMA)


def test_the_schemas_reject_what_the_docs_reject() -> None:
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"version": "1"}, PLUGIN_SCHEMA)  # name is required
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"name": "Go Public"}, PLUGIN_SCHEMA)  # kebab-case
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"name": "x", "author": {"email": "a@b.test"}}, PLUGIN_SCHEMA)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"name": "m", "plugins": []}, MARKETPLACE_SCHEMA)  # owner missing
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {
                "name": "m",
                "owner": {"name": "o"},
                "plugins": [{"name": "p", "source": "plugins/p"}],
            },
            MARKETPLACE_SCHEMA,
        )  # relative sources start with ./


def test_plugin_json_carries_what_the_project_requires() -> None:
    plugin = _load(PLUGIN_JSON)
    assert plugin["name"] == "go-public"
    assert plugin["author"] == {"name": "Andrii Boiko"}
    assert plugin["homepage"] == "https://github.com/B0yko/go-public"
    assert plugin["repository"] == "https://github.com/B0yko/go-public"
    assert plugin["license"] == "Apache-2.0"
    assert plugin["description"].strip()
    assert plugin["keywords"]
    # the wrapper reads the version with a line-based regex: exactly one "version" key
    assert len(re.findall(r'"version"\s*:', PLUGIN_JSON.read_text(encoding="utf-8"))) == 1


def test_marketplace_names_one_plugin_at_the_repository_root() -> None:
    marketplace = _load(MARKETPLACE_JSON)
    assert marketplace["name"] == "go-public"
    assert marketplace["owner"] == {"name": "Andrii Boiko"}  # no email published
    (entry,) = marketplace["plugins"]
    assert entry["name"] == "go-public"
    assert entry["source"] == "."  # the repository root is the plugin root
    assert (ROOT / ".claude-plugin" / "plugin.json").is_file()


def test_no_separate_commands_directory() -> None:
    # Skills are slash commands now; a commands/ file would register a second entry point.
    assert not (ROOT / "commands").exists()


def test_all_versions_agree() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    marketplace = _load(MARKETPLACE_JSON)
    versions = {
        "pyproject.toml": version,
        "plugin.json": _load(PLUGIN_JSON)["version"],
        "go_public.__version__": go_public.__version__,
    }
    if "version" in marketplace:
        versions["marketplace.json"] = marketplace["version"]
    if "version" in marketplace.get("metadata", {}):
        versions["marketplace.json metadata"] = marketplace["metadata"]["version"]
    for entry in marketplace["plugins"]:
        if "version" in entry:
            versions[f"marketplace.json plugin {entry['name']}"] = entry["version"]
    assert set(versions.values()) == {version}, versions

    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"go-public {version}"
