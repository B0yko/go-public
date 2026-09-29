"""`go-public strip`, `show` and `redact` through the CLI."""

from __future__ import annotations

import json
import random
from pathlib import Path

from typer.testing import CliRunner

from go_public.bench import binaries
from go_public.cli import app
from go_public.git.objects import blob_id

from ..conftest import commit_file, git, init_repo
from ..unit import secret_tokens as tok

runner = CliRunner()


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "go-public.toml"
    path.write_text('[identity]\nallow = ["Pat Public <pat@example.com>"]\n[scan]\njobs = 1\n')
    return path


def _repo_state(repo: Path) -> tuple[bytes, bytes, bytes]:
    return (
        git(repo, "for-each-ref"),
        git(repo, "ls-files", "-s"),
        git(repo, "--no-optional-locks", "status", "--porcelain"),
    )


# -- strip -------------------------------------------------------------------------


def test_strip_check_lists_and_exits_1_without_touching_the_file(tmp_path: Path) -> None:
    photo = tmp_path / "photo.jpg"
    photo.write_bytes(binaries.jpeg_with_gps(1.5, 2.5))
    before = photo.read_bytes()

    result = runner.invoke(app, ["strip", str(photo), "--check"])

    assert result.exit_code == 1
    assert "would remove" in result.output
    assert photo.read_bytes() == before


def test_strip_removes_metadata_in_place_and_check_then_passes(tmp_path: Path) -> None:
    photo = tmp_path / "photo.jpg"
    photo.write_bytes(binaries.jpeg_with_gps(1.5, 2.5))

    result = runner.invoke(app, ["strip", str(photo)])
    check = runner.invoke(app, ["strip", str(photo), "--check"])

    assert result.exit_code == 0, result.output
    assert check.exit_code == 0
    assert photo.read_bytes() != binaries.jpeg_with_gps(1.5, 2.5)


def test_strip_handles_several_files_and_leaves_clean_ones_alone(tmp_path: Path) -> None:
    clean = tmp_path / "notes.txt"
    clean.write_text("hello\n")
    png = tmp_path / "shot.png"
    png.write_bytes(binaries.png_with_text("Author", "Some Person"))

    result = runner.invoke(app, ["strip", str(clean), str(png)])

    assert result.exit_code == 0
    assert clean.read_text() == "hello\n"
    assert b"Some Person" not in png.read_bytes()


def test_strip_reports_comment_authors_without_removing_them(tmp_path: Path) -> None:
    docx = tmp_path / "doc.docx"
    original = binaries.minimal_docx(comment_author="Some Reviewer")
    docx.write_bytes(original)

    result = runner.invoke(app, ["strip", str(docx), "--check"])

    assert "reported, not removed" in result.output
    assert docx.read_bytes() == original


def test_strip_rejects_missing_and_symlinked_paths(tmp_path: Path) -> None:
    real = tmp_path / "real.jpg"
    real.write_bytes(binaries.jpeg_with_gps(1.0, 2.0))
    link = tmp_path / "link.jpg"
    link.symlink_to(real)

    assert runner.invoke(app, ["strip", str(tmp_path / "missing.jpg")]).exit_code == 2
    assert runner.invoke(app, ["strip", str(link)]).exit_code == 2


# -- show ----------------------------------------------------------------------------


def _repo_with_secret(tmp_path: Path) -> tuple[Path, str]:
    repo = init_repo(tmp_path / "repo")
    token = tok.aws_access_key(random.Random(21))
    commit_file(repo, "app/settings.txt", f"name = demo\naws = {token}\nend\n", "feat: settings")
    return repo, token


def test_show_masks_secret_spans_and_keeps_the_rest(tmp_path: Path) -> None:
    repo, token = _repo_with_secret(tmp_path)

    result = runner.invoke(
        app, ["show", str(repo), "app/settings.txt", "--config", str(_config(tmp_path))]
    )

    assert result.exit_code == 0, result.output
    assert token not in result.output
    assert token[:4] + "…[len=" in result.output
    assert "name = demo" in result.output and "end" in result.output


def test_show_reads_the_requested_ref(tmp_path: Path) -> None:
    repo, token = _repo_with_secret(tmp_path)
    first = git(repo, "rev-parse", "HEAD").decode().strip()
    commit_file(
        repo, "app/settings.txt", "clean now\n", "fix: remove", date="2024-02-01T00:00:00+00:00"
    )

    old = runner.invoke(app, ["show", str(repo), "app/settings.txt", "--ref", first])
    new = runner.invoke(app, ["show", str(repo), "app/settings.txt"])

    assert token not in old.output and "[len=" in old.output
    assert new.output == "clean now\n"


def test_show_missing_path_and_binary_files_exit_2(tmp_path: Path) -> None:
    repo, _token = _repo_with_secret(tmp_path)
    (repo / "pic.jpg").write_bytes(binaries.jpeg_with_gps(1.0, 2.0))
    git(repo, "add", "pic.jpg")
    git(repo, "commit", "-q", "-m", "feat: pic")

    missing = runner.invoke(app, ["show", str(repo), "nope.txt"])
    binary = runner.invoke(app, ["show", str(repo), "pic.jpg"])
    escaping = runner.invoke(app, ["show", str(repo), "../etc/passwd"])
    directory = runner.invoke(app, ["show", str(repo), "app"])

    assert missing.exit_code == 2
    assert binary.exit_code == 2 and "binary" in binary.output
    assert escaping.exit_code == 2
    assert directory.exit_code == 2


def test_show_does_not_modify_the_repository(tmp_path: Path) -> None:
    repo, _token = _repo_with_secret(tmp_path)
    before = _repo_state(repo)

    runner.invoke(app, ["show", str(repo), "app/settings.txt"])

    assert _repo_state(repo) == before


# -- redact --------------------------------------------------------------------------


def _scan_report(tmp_path: Path, repo: Path) -> dict[str, object]:
    reports = tmp_path / "reports"
    result = runner.invoke(
        app,
        [
            "scan",
            str(repo),
            "--config",
            str(_config(tmp_path)),
            "--report-dir",
            str(reports),
            "--quiet",
        ],
    )
    assert result.exit_code in (0, 1), result.output
    return json.loads((reports / "report.json").read_text())  # type: ignore[no-any-return]


def _secret_finding(report: dict[str, object]) -> dict[str, str]:
    findings = report["findings"]
    assert isinstance(findings, list)
    return next(f for f in findings if f["category"] == "secret")  # type: ignore[no-any-return]


def test_redact_by_fingerprint_replaces_the_secret_only(tmp_path: Path) -> None:
    repo, token = _repo_with_secret(tmp_path)
    finding = _secret_finding(_scan_report(tmp_path, repo))
    target = repo / "app" / "settings.txt"
    state = _repo_state(repo)

    result = runner.invoke(
        app, ["redact", str(target), "--finding", finding["fingerprint"], "--with", "REDACTED"]
    )

    assert result.exit_code == 0, result.output
    assert target.read_text() == "name = demo\naws = REDACTED\nend\n"
    assert token not in result.output
    # The index, refs and history are untouched: only the working-tree file differs.
    after = _repo_state(repo)
    assert after[0] == state[0] and after[1] == state[1]
    assert git(repo, "status", "--porcelain").decode().strip() == "M app/settings.txt"


def test_redact_by_group_id(tmp_path: Path) -> None:
    repo, _token = _repo_with_secret(tmp_path)
    finding = _secret_finding(_scan_report(tmp_path, repo))
    target = repo / "app" / "settings.txt"

    result = runner.invoke(
        app, ["redact", str(target), "--finding", finding["group_id"], "--with", "<removed>"]
    )

    assert result.exit_code == 0, result.output
    assert "<removed>" in target.read_text()


def test_redact_refuses_when_the_group_matches_more_than_one_span(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    token = tok.aws_access_key(random.Random(22))
    commit_file(repo, "a.txt", f"one = {token}\ntwo = {token}\n", "feat: twice")
    finding = _secret_finding(_scan_report(tmp_path, repo))
    target = repo / "a.txt"
    before = target.read_bytes()

    result = runner.invoke(
        app, ["redact", str(target), "--finding", finding["group_id"], "--with", "X"]
    )

    assert result.exit_code == 2
    assert "spans" in result.output
    assert target.read_bytes() == before


def test_redact_refuses_an_unknown_finding_and_leaves_the_file(tmp_path: Path) -> None:
    repo, _token = _repo_with_secret(tmp_path)
    target = repo / "app" / "settings.txt"
    before = target.read_bytes()

    result = runner.invoke(app, ["redact", str(target), "--finding", "deadbeef0000", "--with", "X"])

    assert result.exit_code == 2
    assert target.read_bytes() == before


def test_redact_refuses_a_fingerprint_for_a_different_blob_content(tmp_path: Path) -> None:
    repo, _token = _repo_with_secret(tmp_path)
    finding = _secret_finding(_scan_report(tmp_path, repo))
    target = repo / "app" / "settings.txt"
    target.write_text(target.read_text() + "# edited\n")  # new content, new blob id
    assert blob_id(target.read_bytes()) != finding["fingerprint"]

    result = runner.invoke(
        app, ["redact", str(target), "--finding", finding["fingerprint"], "--with", "X"]
    )

    assert result.exit_code == 2


def test_redact_rejects_symlinks_binary_files_and_empty_placeholders(tmp_path: Path) -> None:
    repo, _token = _repo_with_secret(tmp_path)
    finding = _secret_finding(_scan_report(tmp_path, repo))
    real = repo / "app" / "settings.txt"
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"\x00\x01\x02")

    fp = finding["fingerprint"]
    assert runner.invoke(app, ["redact", str(link), "--finding", fp, "--with", "X"]).exit_code == 2
    assert (
        runner.invoke(app, ["redact", str(binary), "--finding", fp, "--with", "X"]).exit_code == 2
    )
    assert runner.invoke(app, ["redact", str(real), "--finding", fp, "--with", ""]).exit_code == 2
