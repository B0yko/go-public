"""`detect/paths_network.py`: local paths and network identifiers.

conventions.md: plant-shaped strings (here, `/Users/<name>/`-style paths) are
assembled at runtime from parts, never written as one literal.
"""

from __future__ import annotations

from go_public.detect.constants import DEFAULT_ALLOWED_PATH_PREFIXES, DEFAULT_INTERNAL_SUFFIXES
from go_public.detect.paths_network import PathsNetworkDetector


def _detector(**kwargs: object) -> PathsNetworkDetector:
    defaults: dict[str, object] = {
        "allowed_path_prefixes": DEFAULT_ALLOWED_PATH_PREFIXES,
        "internal_suffixes": DEFAULT_INTERNAL_SUFFIXES,
        "deny_domains": (),
    }
    defaults.update(kwargs)
    return PathsNetworkDetector(**defaults)  # type: ignore[arg-type]


_INTERNAL_HOST = "build." + "internal"


def _ip(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def _unix_user_path(name: str) -> str:
    return "/Us" + "ers/" + name + "/"


def _windows_user_path(name: str, sep: str) -> str:
    return "C:" + sep + "Us" + "ers" + sep + name + sep


def test_unix_user_path_is_detected() -> None:
    path = _unix_user_path("bob") + "project/file.py"
    hits = _detector().detect("path is " + path)
    assert [d.rule_id for d in hits] == ["user-path"]
    assert hits[0].value == _unix_user_path("bob")


def test_placeholder_user_path_is_not_detected() -> None:
    assert _detector().detect("path is /Us" + "ers/<user>/project") == []


def test_allowed_prefix_is_not_detected() -> None:
    assert _detector().detect("path is " + _unix_user_path("Shared") + "project") == []
    assert _detector().detect("path is /home/runner/work/repo") == []


def test_windows_user_path_forms_are_detected() -> None:
    single = _detector().detect("path " + _windows_user_path("bob", "\\") + "project")
    doubled = _detector().detect(  # JSON-escaped
        "path " + _windows_user_path("bob", "\\\\") + "project"
    )
    fslash = _detector().detect("path " + _windows_user_path("bob", "/") + "project")
    assert [d.rule_id for d in single] == ["user-path"]
    assert [d.rule_id for d in doubled] == ["user-path"]
    assert [d.rule_id for d in fslash] == ["user-path"]


def test_macos_temp_path_is_detected() -> None:
    hits = _detector().detect("cache at " + "/var/" + "folders/ab/xyz123/T/file")
    assert [d.rule_id for d in hits] == ["macos-temp-path"]


def test_private_ipv4_is_detected_and_loopback_is_not() -> None:
    hits = _detector().detect("server at " + _ip(10, 1, 2, 3))
    assert [d.rule_id for d in hits] == ["private-ip"]
    assert _detector().detect("server at 127.0.0.1") == []


def test_ip_like_version_string_is_not_flagged() -> None:
    # Hard negative from the Data section: not a private range.
    assert _detector().detect("version 1.2.3.4 released") == []


def test_internal_hostname_suffix_is_detected() -> None:
    hits = _detector().detect("deployed to " + _INTERNAL_HOST)
    assert [d.rule_id for d in hits] == ["internal-host"]


def test_host_under_deny_domain_is_detected() -> None:
    detector = _detector(deny_domains=("buildhub.example",))
    hits = detector.detect("api at sub.buildhub.example/v1")
    assert [d.rule_id for d in hits] == ["internal-host"]


def test_gitmodules_url_to_internal_host_is_flagged() -> None:
    content = '[submodule "x"]\n\tpath = x\n\turl = https://' + _INTERNAL_HOST + "/x.git\n"
    hits = _detector().detect(content, is_gitmodules=True)
    rule_ids = {d.rule_id for d in hits}
    assert "private-submodule-url" in rule_ids


def test_gitmodules_check_is_skipped_for_ordinary_blobs() -> None:
    content = '[submodule "x"]\n\tpath = x\n\turl = https://' + _INTERNAL_HOST + "/x.git\n"
    hits = _detector().detect(content, is_gitmodules=False)
    assert not any(d.rule_id == "private-submodule-url" for d in hits)
