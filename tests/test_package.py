"""The installable package: layout, permissions, maintainer scripts."""

from __future__ import annotations

import importlib.util
import io
import subprocess
import tarfile
from pathlib import Path

from conftest import FILES, ROOT, SHELL


def build(tmp_path: Path) -> Path:
    spec = importlib.util.spec_from_file_location("build_ipk", ROOT / "scripts/build_ipk.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_ipk(tmp_path)


def members(blob: bytes) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        return {m.name: m for m in tar.getmembers()}


def test_ipk_layout_permissions_and_scripts(tmp_path: Path) -> None:
    ipk = build(tmp_path)
    with tarfile.open(ipk, "r:gz") as outer:
        names = outer.getnames()
        assert sorted(names) == ["./control.tar.gz", "./data.tar.gz", "./debian-binary"]
        data = outer.extractfile("./data.tar.gz").read()  # type: ignore[union-attr]
        ctrl = outer.extractfile("./control.tar.gz").read()  # type: ignore[union-attr]
    files = members(data)
    assert files["./usr/bin/podkop-watchdog"].mode == 0o755
    assert files["./etc/init.d/podkop-watchdog"].mode == 0o755
    assert files["./etc/config/podkop-watchdog"].mode == 0o600  # may hold the Telegram token
    assert files["./usr/lib/podkop-watchdog/VERSION"].mode == 0o644
    assert all(m.uid == 0 and m.gid == 0 for m in files.values())
    version = (FILES / "usr/lib/podkop-watchdog/VERSION").read_text().strip()
    assert ipk.name == f"podkop-watchdog_{version}_all.ipk"
    with tarfile.open(fileobj=io.BytesIO(ctrl), mode="r:gz") as tar:
        control = tar.extractfile("./control").read().decode()  # type: ignore[union-attr]
        conffiles = tar.extractfile("./conffiles").read().decode()  # type: ignore[union-attr]
        for script in ("postinst", "prerm"):
            body = tar.extractfile(f"./{script}").read()  # type: ignore[union-attr]
            sh = tmp_path / script
            sh.write_bytes(body)
            assert subprocess.run([SHELL, "-n", str(sh)]).returncode == 0
    assert f"Version: {version}" in control and "Architecture: all" in control
    assert conffiles.split() == ["/etc/config/podkop-watchdog"]  # upgrades keep the user's config


def test_every_module_is_packaged_and_syntax_clean(tmp_path: Path) -> None:
    with tarfile.open(build(tmp_path), "r:gz") as outer:
        data = outer.extractfile("./data.tar.gz").read()  # type: ignore[union-attr]
    packaged = {n for n in members(data) if n.endswith(".sh")}
    on_disk = {
        f"./usr/lib/podkop-watchdog/{p.name}" for p in (FILES / "usr/lib/podkop-watchdog").glob("*.sh")
    }
    assert packaged == on_disk
    for sh in [*(FILES / "usr/lib/podkop-watchdog").glob("*.sh"), ROOT / "scripts/install.sh"]:
        assert subprocess.run([SHELL, "-n", str(sh)]).returncode == 0, sh
