"""`bench/realworld.py`: sampling, labels, precision, the leak check and one end-to-end
run on two tiny local stand-ins for the pinned public repositories."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from go_public.bench import realworld as rw
from go_public.bench import run as bench_run
from go_public.model import Finding, FixAction, Location

from ..conftest import commit_file, git, init_repo

BSD3 = (
    "BSD 3-Clause License\n\nRedistribution and use in source and binary forms, with or without "
    "modification, are permitted provided that the following conditions are met:\n"
    "3. Neither the name of the copyright holder nor the names of its contributors may be used.\n"
)
APACHE = "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/\n"


def _finding(
    fp: str, severity: str = "high", rule: str = "pii-email", category: str = "pii"
) -> Finding:
    return Finding(
        fingerprint=fp,
        group_id="g" + fp,
        category=category,
        rule_id=rule,
        severity=severity,
        title="t",
        location=Location(kind="blob", blob="b" + fp, paths=["a.txt"], line=1, column=1),
        location_key=fp,
        fix=FixAction(action="none"),
    )


def _scan(name: str, findings: list[Finding], blobs: int = 100) -> rw.RepoScan:
    repo = next(r for r in rw.REPOS if r.name == name)
    return rw.RepoScan(
        repo=repo,
        facts={"repo": name},
        findings=findings,
        inventory={
            "commits": 5,
            "refs": 1,
            "unique_blobs": blobs,
            "total_blob_bytes": 1000,
            "unreachable_blobs": 0,
        },
        duration_s=1.0,
        clone=Path("."),
    )


def test_allocate_gives_everything_when_the_population_fits() -> None:
    strata = {("a", "high"): 3, ("b", "critical"): 4}
    assert rw.allocate(strata, 50) == strata


def test_allocate_is_proportional_with_a_minimum_of_one_and_sums_to_size() -> None:
    strata = {("a", "high"): 900, ("a", "critical"): 90, ("b", "high"): 8, ("b", "critical"): 2}
    alloc = rw.allocate(strata, 50)
    assert sum(alloc.values()) == 50
    assert all(alloc[k] >= 1 for k in strata)
    assert alloc[("a", "high")] > alloc[("a", "critical")] > alloc[("b", "high")]
    assert all(alloc[k] <= strata[k] for k in strata)


def test_allocate_never_exceeds_a_small_stratum() -> None:
    alloc = rw.allocate({("a", "high"): 1000, ("b", "high"): 2}, 50)
    assert alloc[("b", "high")] == 2 or alloc[("b", "high")] == 1
    assert sum(alloc.values()) == 50


def test_draw_sample_is_deterministic_stratified_and_sized() -> None:
    a = _scan("psf/requests", [_finding(f"a{i}") for i in range(80)] + [_finding("c1", "critical")])
    b = _scan("pallets/flask", [_finding(f"b{i}") for i in range(30)] + [_finding("m", "medium")])
    first = rw.draw_sample([a, b])
    second = rw.draw_sample([b, a])
    assert [i.finding.fingerprint for i in first] == [i.finding.fingerprint for i in second]
    assert len(first) == rw.SAMPLE_SIZE
    assert {i.finding.severity for i in first} <= {"critical", "high"}
    assert "m" not in {i.finding.fingerprint for i in first}
    repos = {i.repo for i in first}
    assert repos == {"psf/requests", "pallets/flask"}
    assert any(i.finding.fingerprint == "c1" for i in first)


def test_draw_sample_takes_everything_when_there_are_few() -> None:
    a = _scan("psf/requests", [_finding("x1"), _finding("x2", "critical")])
    assert len(rw.draw_sample([a])) == 2


def test_rates_exclude_identity_and_count_per_1000_blobs() -> None:
    findings = [_finding("1"), _finding("2"), _finding("3", "medium", "identity", "identity")]
    n = rw.rates(_scan("psf/requests", findings, blobs=500))
    assert n["identity_findings"] == 1
    assert n["findings_excluding_identity"] == 2
    assert n["by_severity"]["high"] == {"count": 2, "per_1000_blobs": 4.0}
    assert n["by_severity"]["medium"]["count"] == 0


def _labels_file(tmp_path: Path, *lines: object) -> Path:
    path = tmp_path / "labels.jsonl"
    path.write_text("".join(json.dumps(x) + "\n" for x in lines), encoding="utf-8")
    return path


def _label(fp: str, verdict: str = "TP", reason: str = "an address") -> dict[str, str]:
    return {"fingerprint": fp, "rule_id": "pii-email", "verdict": verdict, "reason": reason}


def test_read_labels_validates(tmp_path: Path) -> None:
    ok = rw.read_labels(_labels_file(tmp_path, _label("a"), _label("b", "FP")))
    assert set(ok) == {"a", "b"}
    assert rw.read_labels(tmp_path / "missing.jsonl") == {}
    for bad in (
        _label("a", "MAYBE"),
        _label("a", reason=""),
        _label("a", reason="two\nlines"),
        {"fingerprint": "a", "verdict": "TP", "reason": "x"},
    ):
        with pytest.raises(rw.RealWorldError):
            rw.read_labels(_labels_file(tmp_path, bad))
    with pytest.raises(rw.RealWorldError):
        rw.read_labels(_labels_file(tmp_path, _label("a"), _label("a")))


def test_precision_counts_labelled_findings_and_reports_pending() -> None:
    scan = _scan("psf/requests", [_finding(f"f{i}") for i in range(4)])
    sample = rw.draw_sample([scan])
    labels = {
        "f0": _label("f0"),
        "f1": _label("f1"),
        "f2": _label("f2", "FP"),
    }
    prec = rw.precision(sample, labels)
    assert prec["sampled"] == 4
    assert prec["labelled"] == 3
    assert prec["pending"] == 1
    assert prec["overall"]["tp"] == 2
    assert prec["overall"]["fp"] == 1
    assert prec["overall"]["precision"] == pytest.approx(0.667, abs=0.001)
    assert prec["by_rule"]["pii-email"]["labelled"] == 3
    assert rw.stale_labels(sample, {**labels, "zz": _label("zz")}) == ["zz"]


def test_detect_licence() -> None:
    assert rw.detect_licence(BSD3) == "BSD-3-Clause"
    assert rw.detect_licence(APACHE) == "Apache-2.0"
    assert rw.detect_licence("nothing here") is None


def test_assert_no_values_names_rules_not_values() -> None:
    values = {"jo" + "hn.doe@corp.test": {"pii-email"}}
    rw.assert_no_values("counts only", values, "the results")
    with pytest.raises(rw.RealWorldError) as err:
        rw.assert_no_values("see jo" + "hn.doe@corp.test here", values, "the results")
    assert "pii-email" in str(err.value)
    assert "corp.test" not in str(err.value)


def test_disk_usage_counts_allocated_blocks(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(b"x" * 10)
    assert rw.disk_usage_bytes(tmp_path) >= 10


def _stand_in(root: Path, repo: rw.RealWorldRepo, licence: str) -> str:
    path = rw.clone_path(root, repo)
    init_repo(path)
    author = repo.tag.replace(".", "") + "ali" + "***REMOVED***"
    commit_file(path, "LICENSE.txt", licence, "add licence")
    sha = commit_file(path, "AUTHORS", f"- Alice <{author}>\n", "add authors")
    git(path, "tag", "-a", repo.tag, "-m", "release", sha)
    commit_file(path, "later.txt", "after the tag\n", "later work")
    return author


def test_end_to_end_on_two_local_stand_ins(tmp_path: Path) -> None:
    root = tmp_path / "rw"
    emails = []
    for repo, licence in zip(rw.REPOS, (APACHE, BSD3), strict=True):
        emails.append(_stand_in(root, repo, licence))
    labels = tmp_path / "labels.jsonl"
    out = tmp_path / "out"
    outcome = bench_run.run_real_world(root, labels, out, jobs=1, hardware="Test hardware")
    assert {p.name for p in outcome.written} == {"real-world.json", "real-world.md"}
    data = json.loads((out / "real-world.json").read_text())
    assert [r["repo"] for r in data["repos"]] == ["psf/requests", "pallets/flask"]
    assert all(r["licence_ok"] for r in data["repos"])
    assert all(r["tag_kind"] == "annotated" for r in data["repos"])
    # History past the tag is scanned (a full clone), the export ref is the tag.
    assert data["repos"][0]["inventory"]["commits"] == 3
    assert data["precision"]["pending"] == data["precision"]["sampled"] > 0
    text = (out / "real-world.md").read_text() + (out / "real-world.json").read_text()
    assert all(email not in text for email in emails)
    private = root / "private"
    assert stat.S_IMODE(os.stat(private).st_mode) == 0o700
    sample = (private / "sample.jsonl").read_text()
    assert emails[0] in sample
    assert stat.S_IMODE(os.stat(private / "sample.jsonl").st_mode) == 0o600
    # Labelling everything moves it to labelled, and a stale label is reported.
    rows = [json.loads(line) for line in sample.splitlines()]
    label_lines = [_label(r["fingerprint"]) for r in rows] + [_label("stale")]
    labels.write_text("".join(json.dumps(x) + "\n" for x in label_lines))
    outcome = bench_run.run_real_world(root, labels, out, jobs=1, hardware="Test hardware")
    data = json.loads((out / "real-world.json").read_text())
    assert data["precision"]["pending"] == 0
    assert data["precision"]["overall"]["precision"] == 1.0
    assert any("do not match" in line for line in outcome.summary)


def test_missing_tag_is_an_error(tmp_path: Path) -> None:
    root = tmp_path / "rw"
    repo = rw.REPOS[0]
    path = rw.clone_path(root, repo)
    init_repo(path)
    commit_file(path, "LICENSE.txt", APACHE, "add licence")
    with pytest.raises(rw.RealWorldError):
        rw.describe_clone(path, repo)


def test_flask_runtime_target_carries_tag_commit_and_size(tmp_path: Path) -> None:
    root = tmp_path / "rw"
    flask = rw.REPOS[1]
    _stand_in(root, flask, BSD3)
    target = rw.flask_runtime_target(root)
    assert target.gated is False
    assert target.export is False
    assert target.facts["tag"] == "3.1.3"
    assert len(target.facts["tag_commit"]) == 12
    assert target.facts["clone_size_mb"] >= 0
