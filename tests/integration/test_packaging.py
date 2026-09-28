"""The built wheel carries the vendored gitleaks rule set and its licence
(product spec item 2 / stage-2.md 2a): `uv build` into a throwaway directory, then
check the wheel's own file listing.
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _uv() -> str:
    return shutil.which("uv") or str(Path.home() / ".local" / "bin" / "uv")


def test_wheel_contains_vendored_gitleaks_files(tmp_path: Path) -> None:
    out_dir = tmp_path / "dist"
    subprocess.run(
        [_uv(), "build", "--out-dir", str(out_dir)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    wheels = list(out_dir.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
    assert "go_public/rules/gitleaks.toml" in names
    assert "go_public/rules/LICENSE.gitleaks" in names
