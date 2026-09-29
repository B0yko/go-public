"""The documentation: README blocks equal the committed results, every command and flag the
docs name exists, the statements the README must make are there, and the CI, release and
issue-form files are well-formed.

The README's tables are copied from `bench/results/*.md` by `scripts/sync_readme.py`. These
tests check that copy (`test_readme_is_in_sync`) and, independently, that the numbers in the
copied tables equal the JSON results files the bench wrote.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shlex
import sys
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from go_public.cli import app
from go_public.config import Config
from tests.test_plugin_support import CLICK_APP, check_tokens, code_snippets, is_group

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
RESULTS = ROOT / "bench" / "results"
DOC_FILES = [README, ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md", ROOT / "CHANGELOG.md"]
NOREPLY = "142843700+B0yko@users.noreply.github.com"  # the maintainer's public identity
UVX_PREFIX = "uvx --from git+https://github.com/B0yko/go-public "


def _load_sync() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "sync_readme", ROOT / "scripts" / "sync_readme.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SYNC = _load_sync()


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _block(name: str) -> str:
    match = re.search(
        rf"<!-- BEGIN generated:{name} -->\n(.*?)<!-- END generated:{name} -->",
        _readme(),
        re.DOTALL,
    )
    assert match, f"README has no block {name!r}"
    return match.group(1)


def _outside_blocks(text: str) -> str:
    return re.sub(
        r"<!-- BEGIN generated:.*?<!-- END generated:[a-z0-9-]+ -->", "", text, flags=re.DOTALL
    )


def _tables(text: str) -> list[list[list[str]]]:
    """Markdown tables of `text` as rows of stripped cells (header first, rule row dropped)."""
    tables: list[list[list[str]]] = []
    current: list[list[str]] = []
    for line in [*text.splitlines(), ""]:
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not all(re.fullmatch(r":?-+:?", c) for c in cells):
                current.append(cells)
        elif current:
            tables.append(current)
            current = []
    return tables


def _table(text: str, *header_start: str) -> list[list[str]]:
    for table in _tables(text):
        if tuple(table[0][: len(header_start)]) == header_start:
            return table[1:]
    raise AssertionError(f"no table starting with {header_start}")


def _json(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((RESULTS / f"{name}.json").read_text(encoding="utf-8"))
    return data


# -- the README is a copy of the results ------------------------------------------


def test_readme_is_in_sync() -> None:
    assert SYNC.render(_readme()) == _readme(), "run `uv run python scripts/sync_readme.py`"


def test_every_config_key_is_documented_and_in_the_readme_table() -> None:
    keys = {
        f"{table}.{key}"
        for table, field in Config.model_fields.items()
        for key in field.annotation.model_fields
    }
    assert keys == set(SYNC.KEY_DOCS)
    table = _table(_block("config-reference"), "Key", "Type", "Default", "Meaning")
    assert {row[0].strip("`") for row in table} == keys


def test_config_defaults_in_the_readme_are_the_model_defaults() -> None:
    defaults = Config()
    rows = {
        r[0].strip("`"): r
        for r in _table(_block("config-reference"), "Key", "Type", "Default", "Meaning")
    }
    assert rows["scan.fail_on"][2] == f'`"{defaults.scan.fail_on}"`'
    assert rows["scan.max_scan_mb"][2] == f"`{defaults.scan.max_scan_mb}`"
    assert rows["files.warn_mb"][2] == f"`{defaults.files.warn_mb}`"
    assert rows["files.high_mb"][2] == f"`{defaults.files.high_mb}`"
    assert rows["secrets.generic_entropy"][2] == f"`{defaults.secrets.generic_entropy}`"
    toml_block = re.search(r"```toml\n(.*?)```", _block("config-reference"), re.DOTALL)
    assert toml_block
    long_lists = tomllib.loads(toml_block.group(1))
    assert long_lists["files"]["sensitive_files"] == defaults.files.sensitive_files
    assert long_lists["files"]["internal_notes"] == defaults.files.internal_notes
    assert long_lists["trailers"]["flag"] == defaults.trailers.flag
    assert long_lists["network"]["internal_suffixes"] == defaults.network.internal_suffixes


def test_synthetic_table_equals_the_json() -> None:
    data = _json("synthetic-small-2-6")
    rows = {r[0]: r for r in _table(_block("results-synthetic"), "Class")}
    assert set(rows) == set(data["classes"])
    for name, c in data["classes"].items():
        assert rows[name][1:] == [
            str(c["plants"]),
            str(c["expected_findings"]),
            str(c["tp"]),
            str(c["fn"]),
            str(c["fp"]),
            f"{c['recall']:.3f}",
            f"{c['precision']:.3f}",
            f"{c['per_seed_min_recall']:.3f}",
            f"{c['per_seed_min_precision']:.3f}",
            f">= {c['gate']:.2f}",
            "pass" if c["pass"] else "FAIL",
        ], name


def test_head_only_table_equals_the_json() -> None:
    data = _json("head-only-compare-small-2-6")
    rows = {r[0]: r for r in _table(_block("results-head-only"), "Location")}
    expected = {**data["by_location"], "all locations": data["overall"]}
    assert set(rows) == set(expected)
    for name, v in expected.items():
        assert rows[name][1:] == [
            str(v["expected"]),
            str(v["full_found"]),
            f"{v['full_recall']:.3f}",
            str(v["head_only_found"]),
            f"{v['head_only_recall']:.3f}",
        ], name


def test_gitleaks_tables_equal_the_json() -> None:
    data = _json("gitleaks-small-2-6")
    block = _block("results-gitleaks")
    summary = data["summary"]

    locations = {r[0]: r for r in _table(block, "Location", "Expected")}
    assert len(locations) == len(data["locations"])
    for loc in data["locations"]:
        in_scope = loc["expected"] - loc["outside_gitleaks_scope"]
        assert locations[loc["location"]][1:] == [
            str(loc["expected"]),
            str(loc["outside_gitleaks_scope"]),
            str(loc["in_checkout"]),
            f"{loc['go_public']}/{loc['expected']}",
            f"{loc['git']}/{in_scope}",
            f"{loc['git_no_replace']}/{in_scope}",
            f"{loc['dir']}/{loc['in_checkout']}",
        ], loc["location"]

    recall = {r[0]: r for r in _table(block, "Tool", "Found")}
    names = {
        "go-public (full scan)": "go_public",
        "gitleaks git (all refs)": "git",
        "gitleaks git (replace refs ignored)": "git_no_replace",
        "gitleaks dir (checkout of HEAD)": "dir",
    }
    assert set(recall) == set(names)
    total, scope, head = (
        summary["expected"],
        summary["expected_in_gitleaks_git_scope"],
        summary["expected_at_head"],
    )
    for label, key in names.items():
        s = summary[key]
        assert recall[label][1:] == [
            f"{s['found']}/{total}",
            f"{s['found'] / total:.3f}",
            f"{s['found_in_git_scope']}/{scope} ({s['found_in_git_scope'] / scope:.3f})",
            f"{s['found_at_head']}/{head} ({s['found_at_head'] / head:.3f})",
        ], label

    by_class = {r[0]: r for r in _table(block, "Tool", "secret-generic", "secret-vendor")}
    labels = {"go-public": "go_public", **{k: v for k, v in names.items() if v != "go_public"}}
    assert set(by_class) == set(labels)
    for label, key in labels.items():
        classes = summary[key]["by_class"]
        assert by_class[label][1:] == [
            f"{classes[c]['found']}/{classes[c]['expected']}"
            for c in ("secret-generic", "secret-vendor")
        ], label

    timing = {r[0]: r for r in _table(block, "Tool", "Total over fixtures, s")}
    timing_names = {
        "go-public scan (CLI, default jobs)": "go_public",
        "gitleaks git (all refs)": "git",
        "gitleaks git (replace refs ignored)": "git_no_replace",
        "gitleaks dir (checkout of HEAD)": "dir",
    }
    assert set(timing) == set(timing_names)
    for label, key in timing_names.items():
        t = data["timing"][key]
        assert timing[label][1:] == [
            f"{t['wall_s_total_median']:.2f}",
            f"{t['wall_s_median_per_fixture']:.2f}",
        ], label

    blind = data["blind_spot_secrets"]
    rows = {r[0]: r for r in _table(block, "Blind spot")}
    assert set(rows) == set(blind["kinds"])
    for kind, v in blind["kinds"].items():
        assert rows[kind][1:] == [
            str(v["plants"]),
            *(f"{v['found'][t]}/{v['plants']}" for t in blind["tools"]),
        ], kind


def test_export_tables_equal_the_json() -> None:
    data = _json("export-verify-small-2-6")
    block = _block("results-export")
    tables = [t for t in _tables(block) if t[0][0] == "Seed"]
    assert len(tables) == 2
    for table, mode in zip(tables, ("squash", "keep-history"), strict=True):
        seeds = data["modes"][mode]["seeds"]
        assert [r[0] for r in table[1:]] == [str(s["seed"]) for s in seeds] + ["all"]
        for row, s in zip(table[1:], seeds, strict=False):
            assert row[1:7] == [
                f"{s['history_only_eliminated']}/{s['history_only_total']}",
                f"{s['head_auto_eliminated']}/{s['head_auto_total']}",
                str(s["residual_true"]),
                str(s["residual_false_positives"]),
                str(s["left_by_design"]) if s["left_by_design"] else "-",
                "yes" if s["immutable"] else "NO",
            ], (mode, row[0])
        t = data["modes"][mode]["total"]
        assert table[-1][1:] == [
            f"{t['history_only_eliminated']}/{t['history_only_total']}",
            f"{t['head_auto_eliminated']}/{t['head_auto_total']}",
            str(t["residual_true"]),
            str(t["residual_false_positives"]),
            str(t["left_by_design"]) if t["left_by_design"] else "-",
            "yes" if data["modes"][mode]["immutable_all"] else "NO",
            "pass" if data["modes"][mode]["pass"] else "FAIL",
        ], mode


def test_real_world_tables_equal_the_json() -> None:
    data = _json("real-world")
    block = _block("results-real-world")
    repos = {r[0]: r for r in _table(block, "Repository", "Tag")}
    assert set(repos) == {r["repo"] for r in data["repos"]}
    for r in data["repos"]:
        row = repos[r["repo"]]
        assert row[1] == r["tag"]
        assert row[2] == f"`{r['tag_commit'][:12]}`"
        assert row[3] == f"{r['clone_size_mb']:.1f} MB"
        assert row[5] == f"{r['inventory']['commits']:,}"
        assert row[6] == f"{r['inventory']['unique_blobs']:,}"

    noise = {r[0]: r for r in _table(block, "Repository", "Critical")}
    for r in data["repos"]:
        n = r["noise"]
        cells = [
            f"{n['by_severity'][sev]['count']} ({n['by_severity'][sev]['per_1000_blobs']:.2f})"
            for sev in ("critical", "high", "medium", "low", "info")
        ]
        cells.append(f"{n['findings_excluding_identity']} ({n['per_1000_blobs_all']:.2f})")
        cells.append(str(n["identity_findings"]))
        assert noise[r["repo"]][1:] == cells, r["repo"]
        for rule, count in n["by_rule"].items():
            assert f"| {rule} | {count} |" in block, (r["repo"], rule)

    p = data["precision"]["overall"]
    assert (
        f"Overall: {p['tp']} true positives, {p['fp']} false positives among {p['labelled']} "
        f"labelled findings; precision {p['precision']:.3f}."
    ) in block


def test_runtime_tables_equal_the_json() -> None:
    data = _json("runtime")
    block = _block("results-runtime")
    tables = [t for t in _tables(block) if t[0][0] == "Command"]
    assert len(tables) == len(data["targets"])
    keys = [
        ("scan, default", "scan_default_jobs"),
        ("scan, `--jobs 1`", "scan_jobs_1"),
        ("squash export", "squash_export"),
    ]
    for table, target in zip(tables, data["targets"], strict=True):
        rows = {r[0]: r for r in table[1:]}
        for label, key in keys:
            if key not in target:
                assert label not in rows
                continue
            m = target[key]
            expected = [
                f"{m['wall_s_median']:.2f}",
                f"{m['peak_rss_mb_median']:.0f}",
                f"{m['blobs_per_s']:.0f}" if "blobs_per_s" in m else "",
            ]
            assert rows[label][1:4] == expected, (target["label"], label)
        inventory = target["scan_default_jobs"]["inventory"]
        assert f"{inventory['commits']:,} commits" in block
        assert f"{inventory['unique_blobs']:,} unique blobs" in block


def test_blind_spot_table_equals_the_json() -> None:
    data = _json("blind-spots-small-0_1")
    block = _block("results-blind-spots")
    rows = {r[0]: r for r in _table(block, "Blind spot")}
    assert set(rows) == {k.removeprefix("blind-") for k in data["kinds"]}
    for kind, v in data["kinds"].items():
        assert rows[kind.removeprefix("blind-")][1:] == [
            str(v["plants"]),
            str(v["detected"]),
            f"{v['recall']:.3f}",
            ", ".join(v["detected_by"]) or "-",
        ], kind
    o = data["overall"]
    assert (
        f"Overall: {o['detected']} of {o['plants']} detected (recall {o['recall']:.3f})." in block
    )


def test_at_a_glance_equals_the_json() -> None:
    rows = _table(_block("at-a-glance"), "Measure", "Result", "For comparison")
    cells = {re.sub(r"^\[([^\]]+)\]\(#[a-z-]+\)$", r"\1", r[0]): r[1:] for r in rows}

    def row(prefix: str) -> list[str]:
        (match,) = [cells[k] for k in cells if k.startswith(prefix)]
        return match

    def rate(found: int, total: int) -> str:
        return f"{found / total:.3f} ({found}/{total})"

    classes = list(_json("synthetic-small-2-6")["classes"].values())
    tp, fn, fp = (sum(c[k] for c in classes) for k in ("tp", "fn", "fp"))
    assert row("Recall, held-out")[0] == f"{tp / (tp + fn):.3f}"
    assert row("Recall, held-out")[1] == (
        f"{tp}/{tp + fn} expected findings; lowest class {min(c['recall'] for c in classes):.3f}"
    )
    assert row("Precision, held-out")[0] == f"{tp / (tp + fp):.3f}"
    assert row("Precision, held-out")[1] == (
        f"{fp} false positives; lowest class {min(c['precision'] for c in classes):.3f}"
    )

    head = _json("head-only-compare-small-2-6")["overall"]
    assert row("Recall, full scan")[0] == f"{head['full_found'] / head['expected']:.3f}"
    assert row("Recall, full scan")[1] == (
        f"`--head-only`: {rate(head['head_only_found'], head['expected'])}"
    )

    gitleaks = _json("gitleaks-small-2-6")
    summary, timing = gitleaks["summary"], gitleaks["timing"]
    total = summary["expected"]
    assert row("Secret recall")[0] == f"{summary['go_public']['found'] / total:.3f}"
    assert f"`gitleaks git`: {rate(summary['git']['found'], total)}" in row("Secret recall")[1]
    assert f"`gitleaks dir`: {rate(summary['dir']['found'], total)}" in row("Secret recall")[1]
    assert row("Wall time")[0] == f"{timing['go_public']['wall_s_total_median']:.2f} s"
    assert row("Wall time")[1].endswith(f"{timing['git']['wall_s_total_median']:.2f} s")

    modes = _json("export-verify-small-2-6")["modes"]
    squash, keep = modes["squash"]["total"], modes["keep-history"]["total"]
    assert row("Export")[0] == f"{squash['history_only_eliminated']}/{squash['history_only_total']}"
    assert row("Export")[1].startswith(f"squash, {squash['residual_true']} residual")
    assert f"{keep['history_only_eliminated']}/{keep['history_only_total']}" in row("Export")[1]

    p = _json("real-world")["precision"]["overall"]
    assert row("Precision, real-world")[0] == f"{p['precision']:.3f}"
    assert row("Precision, real-world")[1].startswith(f"{p['tp']}/{p['labelled']} ")

    medium = next(t for t in _json("runtime")["targets"] if t["gated"])["scan_default_jobs"]
    assert row("Full scan, synthetic medium")[0] == f"{medium['wall_s_median']:.2f} s"
    assert row("Full scan, synthetic")[1].startswith(
        f"{medium['peak_rss_mb_median']:.0f} MB peak RSS"
    )
    assert f"{medium['inventory']['unique_blobs']:,} unique blobs" in row("Full scan, synthetic")[1]


def test_every_block_names_its_command_and_the_frozen_detector_commit() -> None:
    frozen = _json("synthetic-small-2-6")["meta"]["detector_commit"]
    for name in SYNC.BLOCKS:
        if not name.startswith("results-"):
            continue
        block = _block(name)
        assert re.search(r"```sh\ngo-public bench .*\n```", block), name
        assert "Mac Studio M4 Max, 128 GB" in block, name
        assert "go-public 0.1.0" in block, name
        assert f"detector commit `{frozen}`" in block, name
        assert re.search(r"Run on \d{4}-\d{2}-\d{2} \(UTC\)", block), name


def test_every_bench_command_in_the_results_blocks_can_be_run_literally() -> None:
    """`bench` requires `--out`, and the runtime table has a flask row, which needs the clone."""
    for name in SYNC.BLOCKS:
        if not name.startswith("results-"):
            continue
        command = re.search(r"```sh\n(go-public bench .*)\n```", _block(name))
        assert command, name
        assert "--out " in command.group(1), name
        if name == "results-runtime":
            assert "--real-world-dir " in command.group(1)


def test_the_medium_fixture_has_the_binaries_the_readme_states() -> None:
    import random

    from go_public.bench import medium

    class Ctx:
        branch_tip = {medium.MAIN: "x"}
        public_identity = None

        def __init__(self) -> None:
            self.blobs: list[bytes] = []

        def blob(self, data: bytes) -> int:
            self.blobs.append(data)
            return len(self.blobs)

        def commit(self, ref: str, **kwargs: Any) -> None:
            self.branch_tip[ref] = "y"

        def request_tag(self, *args: Any, **kwargs: Any) -> None:
            pass

    ctx = Ctx()
    medium.build_history(ctx, random.Random(100), medium.MediumShape())  # type: ignore[arg-type]
    png = sum(b.startswith(b"\x89PNG") for b in ctx.blobs)
    jpeg = sum(b.startswith(b"\xff\xd8\xff") for b in ctx.blobs)
    assert (png, jpeg) == (32, 8)
    assert f"{png + jpeg} binary files ({png} PNG and {jpeg} JPEG" in _readme()


def test_no_result_number_is_typed_into_the_prose() -> None:
    prose = _outside_blocks(_readme())
    prose = re.sub(r"```.*?```", "", prose, flags=re.DOTALL)
    assert not re.search(r"\b[01]\.\d{3}\b", prose), (
        "a recall or precision figure sits in the prose"
    )
    assert not re.search(
        r"\b\d[\d,]*(\.\d+)? ?(s|ms|MB|GB|%)(?![\w-])", prose.replace("100 MiB", "")
    ), "a measured figure sits in the prose"


# -- commands and flags named in the docs exist -------------------------------------


def _command_line(snippet: str) -> list[str] | None:
    text = snippet.removeprefix("uv run ").removeprefix(UVX_PREFIX)
    if not re.match(r"go-public(\s|$)", text) or text.startswith("go-public:"):
        return None
    try:
        return [t for t in shlex.split(text)[1:] if t != "..."]
    except ValueError:
        return None


def _check(tokens: list[str], source: str) -> None:
    """`check_tokens`, but a prose mention such as `go-public bench --real-world-dir` may end
    on a flag that takes a value."""
    for extra in range(4):
        try:
            check_tokens([*tokens, *["<value>"] * extra], source=source)
        except AssertionError as error:
            if "needs a value" not in str(error) and "missing argument" not in str(error):
                raise
            if extra == 3:
                raise
        else:
            return


@pytest.mark.parametrize("path", DOC_FILES, ids=lambda p: p.name)
def test_every_go_public_command_in_the_docs_exists(path: Path) -> None:
    checked = 0
    for snippet in code_snippets(path.read_text(encoding="utf-8")):
        if snippet.text.startswith("#"):
            continue
        tokens = _command_line(snippet.text)
        if not tokens or tokens[0].startswith("<"):
            continue
        _check(tokens, f"{path.name}:{snippet.line}: {snippet.text}")
        checked += 1
    if path == README:
        assert checked >= 12


def test_every_flag_in_the_docs_exists() -> None:
    known: set[str] = set()

    def collect(command: Any) -> None:
        for param in command.params:
            if param.param_type_name == "option":
                known.update([*param.opts, *param.secondary_opts])
        if is_group(command):
            for sub in command.commands.values():
                collect(sub)

    collect(CLICK_APP)
    external = {"--public", "--source", "--push", "--mirror", "--all", "--tags", "--locked"}
    for path in DOC_FILES:
        text = path.read_text(encoding="utf-8")
        if path == README:
            text = _outside_blocks(text)
        for snippet in code_snippets(text):
            for flag in re.findall(
                r"(?<![\w-])--[a-z][a-z-]*", snippet.text.replace(UVX_PREFIX, "")
            ):
                assert flag in known or flag in external, f"{path.name}:{snippet.line}: {flag}"


@pytest.mark.parametrize("command", ["scan", "export"])
def test_the_readme_lists_every_flag_of_scan_and_export(command: str) -> None:
    row = next(
        line
        for line in _outside_blocks(_readme()).splitlines()
        if line.startswith(f"| `{command} <repo>")
    )
    for param in CLICK_APP.commands[command].params:
        if param.param_type_name != "option" or param.opts == ["--help"] or param.hidden:
            continue
        names = [*param.opts, *param.secondary_opts]
        assert any(f"`{n}`" in row or n in row for n in names), (command, names)


# -- statements the README must make ------------------------------------------------


def test_the_readme_opens_with_the_logo_in_both_themes() -> None:
    hero = _readme().partition("\n## ")[0]
    assert hero.startswith('<p align="center">')
    assert 'alt="go-public"' in hero
    for theme in ("light", "dark"):
        path = f"docs/img/logo-{theme}.svg"
        assert f'media="(prefers-color-scheme: {theme})" srcset="{path}"' in hero, theme
        svg = (ROOT / path).read_text(encoding="utf-8")
        assert svg.startswith("<svg ") and "<!--" not in svg and "<metadata" not in svg, path
    assert "Audit a private git repository before you open-source it." in hero


def test_the_readme_has_its_sections_and_install_commands() -> None:
    text = _readme()
    for heading in (
        "Quickstart",
        "How it works",
        "The fix plan",
        "Configuration",
        "Where the config is found",
        "Globs",
        "Exit codes",
        "Results and benchmarks",
        "Limitations",
        "Roadmap",
        "Data and licences",
        "Licence",
    ):
        assert re.search(rf"^#+ {re.escape(heading)}$", text, re.MULTILINE), heading
    for command in (
        "/plugin marketplace add B0yko/go-public",
        "/plugin install go-public@go-public",
        "/go-public",
    ):
        assert f"\n{command}\n" in text, command
    quickstart = text.split("## Quickstart")[1].split("\n### ")[0]
    for sub in ("demo", "init", "scan", "export"):
        assert (
            f"{UVX_PREFIX}go-public {sub} " in quickstart
            or f"{UVX_PREFIX}go-public {sub}\n" in quickstart
        ), sub


def test_the_readme_states_what_it_must_state() -> None:
    text = " ".join(_outside_blocks(_readme()).split()).lower()
    required = [
        "the report is local and private",
        "written outside the repository",
        "does not replace rotating it",
        "not legal advice",
        "publish the export as a **new** repository",
        "never make the existing private repository public",
        "every ref, pull-request ref, issue, wiki page and actions log",
        "`git clone --mirror`",
        "only `go-public bench --real-world-dir` uses the network",
        "commit ids change, signatures are dropped",
        "licence history is kept as it was",
        "macos 13, 14 and 15 (arm64 and x86_64)",
        "manylinux (aarch64 and x86_64)",
        "windows (win32, amd64, arm64)",
        "needs a c++ toolchain",
        "`<id>+<username>@users.noreply.github.com`",
        "windows is untested",
        "sha-256 repositories** exit with code 3",
        "upper bound",
        "written by the same author",
        "no named-entity recognition",
        "archives other than ooxml are not scanned",
        "hosted surfaces are not scanned",
        "labels are by the author",
        "a url password that contains a space",
        "one vat-like number",
        "single-branch",
        "gitleaks's, so",
        "pathspec",
        "last matching pattern wins",
        "apache-2.0",
        "psf/requests",
        "pallets/flask",
        "src/go_public/rules/gitleaks.toml",
        "third_party/gitleaks/",
        "rfc 1918",
    ]
    for needle in required:
        assert needle in text, needle
    for exit_code in ("| 0 |", "| 1 |", "| 2 |", "| 3 |"):
        assert exit_code in _readme()


def test_the_readme_names_and_links_the_alternatives() -> None:
    text = _readme()
    for name, url in {
        "gitleaks": "https://github.com/gitleaks/gitleaks",
        "trufflehog": "https://github.com/trufflesecurity/trufflehog",
        "detect-secrets": "https://github.com/Yelp/detect-secrets",
        "GitHub secret scanning": "https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning",
        "push protection": "https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection",
        "git-filter-repo": "https://github.com/newren/git-filter-repo",
        "BFG": "https://rtyley.github.io/bfg-repo-cleaner/",
        "Copybara": "https://github.com/google/copybara",
        "exiftool": "https://exiftool.org/",
        "mat2": "https://0xacab.org/jvoisin/mat2",
        "ScanCode": "https://github.com/aboutcode-org/scancode-toolkit",
        "licensee": "https://github.com/licensee/licensee",
        "REUSE": "https://reuse.software/",
        "Presidio": "https://presidio.dataprivacystack.org/",
    }.items():
        assert f"]({url})" in text, name


def test_the_screenshot_is_referenced_and_committed() -> None:
    """The report screenshot comes in a light and a dark variant, picked by the reader's theme."""
    shots = set(re.findall(r'(?:src|srcset)="(docs/img/report[^"]*)"', _readme()))
    assert shots == {"docs/img/report.png", "docs/img/report-dark.png"}
    for shot in shots:
        assert (ROOT / shot).is_file(), shot


def test_the_host_product_name_appears_only_in_the_intro_and_install_section() -> None:
    name = "Clau" + "de Code"
    text = _readme()
    intro, _, rest = text.partition("\n## ")
    assert name in intro  # the description under the logo
    allowed = ("Quickstart",)
    for section in ("## " + rest).split("\n## ")[0:]:
        heading = section.splitlines()[0].removeprefix("## ").strip()
        if heading in allowed:
            continue
        assert name not in section, f"{name!r} in section {heading!r}"


def test_no_document_mentions_assistants_or_how_the_product_was_written() -> None:
    words = [
        "clau" + "de",
        "anthro" + "pic",
        "co" + "dex",
        "copi" + "lot",
        "chat" + "gpt",
        "generated " + "by",
        "generated " + "with",
        "co-authored-by: ",
    ]
    files = [ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md", ROOT / "CHANGELOG.md"]
    files += sorted((ROOT / ".github").rglob("*.yml"))
    files += [ROOT / "scripts" / "sync_readme.py", ROOT / "scripts" / "ci-check-git.sh"]
    for path in files:
        lowered = path.read_text(encoding="utf-8").lower()
        for word in words:
            assert word not in lowered, f"{path.relative_to(ROOT)}: {word!r}"
    readme = _readme().lower()
    for word in words[1:]:
        assert word not in readme, word


def test_docs_hold_no_email_other_than_placeholders_and_no_user_paths() -> None:
    email = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
    for path in DOC_FILES:
        text = path.read_text(encoding="utf-8")
        for found in email.findall(text):
            assert found.endswith(("@example.com", "@example.org")) or found == NOREPLY, (
                f"{path.name}: {found}"
            )
        paths = re.findall(r"/(?:Users|home)/[a-z][\w-]*/", text)
        assert set(paths) <= {"/home/runner/"}, f"{path.name}: {paths}"
    assert not email.search((ROOT / "SECURITY.md").read_text(encoding="utf-8"))


# -- images ---------------------------------------------------------------------------


def test_every_image_in_the_repository_passes_strip_check() -> None:
    skip = {".git", ".venv", ".mypy_cache", ".ruff_cache", ".pytest_cache", "__pycache__"}
    images = [
        p
        for p in ROOT.rglob("*")
        if p.is_file()
        and p.suffix.lower()
        in {".png", ".jpg", ".jpeg", ".webp", ".pdf", ".docx", ".xlsx", ".pptx"}
        and not skip & set(p.relative_to(ROOT).parts)
    ]
    assert any(p.name == "report.png" for p in images)
    runner = CliRunner()
    for image in images:
        result = runner.invoke(app, ["strip", "--check", str(image)])
        assert result.exit_code == 0, f"{image.relative_to(ROOT)}: {result.output}"


# -- CI, release and issue forms -----------------------------------------------------


def _yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    # YAML 1.1 reads the key `on` as the boolean True.
    return workflow.get("on", workflow.get(True))


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return list(job["steps"])


def _runs(job: dict[str, Any]) -> list[str]:
    return [s["run"] for s in _steps(job) if "run" in s]


def _uses(workflow: dict[str, Any]) -> list[str]:
    return [s["uses"] for job in workflow["jobs"].values() for s in _steps(job) if "uses" in s]


def test_ci_workflow() -> None:
    ci = _yaml(ROOT / ".github" / "workflows" / "ci.yml")
    assert set(_triggers(ci)) == {"push", "pull_request"}
    assert ci["permissions"] == {"contents": "read"}
    test = ci["jobs"]["test"]
    assert test["strategy"]["matrix"]["os"] == ["ubuntu-latest", "macos-latest"]
    assert test["runs-on"] == "${{ matrix.os }}"
    runs = _runs(test)
    for command in (
        "uv run ruff check",
        "uv run ruff format --check",
        "uv run mypy src",
        "uv run pytest tests",
        "uv run python scripts/sync_readme.py --check",
        'uv run go-public bench --seeds 0,1 --size tiny --gate --out "$RUNNER_TEMP/bench"',
    ):
        assert command in runs, command
    assert any("scripts/ci-check-git.sh" in r for r in runs)
    scan = ci["jobs"]["self-scan"]
    checkout = next(s for s in _steps(scan) if s.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["fetch-depth"] == 0
    assert "uv run go-public scan . --include-unreachable --fail-on medium" in _runs(scan)
    assert any(s["uses"].startswith("astral-sh/setup-uv@") for s in _steps(test) if "uses" in s)
    for used in _uses(ci):
        assert re.fullmatch(r"[\w./-]+@v\d[\w.]*", used), used
    for job in ci["jobs"].values():
        for run in _runs(job):
            tokens = _command_line(run.removeprefix("uv run ").split("\n")[0])
            if tokens:
                _check(tokens, run)


def test_ci_makes_no_network_calls_to_paid_apis() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").lower()
    for word in ("secrets.", "api_key", "openai", "openrouter", "curl "):
        assert word not in text, word


def test_release_workflow() -> None:
    release = _yaml(ROOT / ".github" / "workflows" / "release.yml")
    triggers = _triggers(release)
    assert triggers["push"] == {"tags": ["v*"]}
    assert "workflow_dispatch" in triggers
    assert release["permissions"] == {"contents": "read"}
    github_release = release["jobs"]["github-release"]
    assert github_release["permissions"] == {"contents": "write"}
    assert "push" in github_release["if"]
    body = "\n".join(_runs(github_release))
    assert "uv build" in body
    assert "gh release view" in body and "gh release create" in body and "gh release upload" in body
    assert "CHANGELOG.md" in body
    pypi = release["jobs"]["pypi"]
    assert "workflow_dispatch" in pypi["if"]
    assert pypi["environment"] == "pypi"
    assert pypi["permissions"]["id-token"] == "write"
    assert any(s.get("uses", "").startswith("pypa/gh-action-pypi-publish@") for s in _steps(pypi))
    assert "id-token" not in github_release["permissions"]


def test_the_changelog_has_a_section_for_the_current_version() -> None:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    lines = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(f"## [{version}]"))
    notes = []
    for line in lines[start + 1 :]:
        if line.startswith("## ["):
            break
        notes.append(line)
    assert "".join(notes).strip(), "the release notes for this version are empty"


FORMS = ROOT / ".github" / "ISSUE_TEMPLATE"


def test_issue_forms() -> None:
    assert {p.name for p in FORMS.glob("*.yml")} == {
        "bug.yml",
        "config.yml",
        "false-negative.yml",
        "false-positive.yml",
    }
    for name in ("bug", "false-negative", "false-positive"):
        form = _yaml(FORMS / f"{name}.yml")
        assert {"name", "description", "body"} <= set(form)
        ids = [item["id"] for item in form["body"] if "id" in item]
        assert len(ids) == len(set(ids))
        assert any(item["type"] == "input" and item["id"] == "version" for item in form["body"])
    for name in ("false-negative", "false-positive"):
        form = _yaml(FORMS / f"{name}.yml")
        warning = form["body"][0]
        assert warning["type"] == "markdown"
        assert "do not paste real values" in warning["attributes"]["value"].lower()
        confirmation = next(item for item in form["body"] if item["type"] == "checkboxes")
        assert all(option["required"] for option in confirmation["attributes"]["options"])
    config = _yaml(FORMS / "config.yml")
    assert config["blank_issues_enabled"] is False
    assert (
        config["contact_links"][0]["url"]
        == "https://github.com/B0yko/go-public/security/advisories/new"
    )


def test_security_policy_uses_private_reporting_and_synthetic_reproductions() -> None:
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "https://github.com/B0yko/go-public/security/advisories/new" in text
    assert "private vulnerability reporting" in text.lower()
    assert "synthetic reproduction is enough" in text
    assert "never paste the real value" in text.lower()
