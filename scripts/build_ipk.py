#!/usr/bin/env python3
"""Build an opkg package (all architectures) from files/ without the OpenWrt SDK.

    python3 scripts/build_ipk.py [outdir]    -> outdir/podkop-watchdog_<version>_all.ipk

The package is architecture-independent (POSIX shell). Install on the router:
    opkg install ./podkop-watchdog_*_all.ipk      (OpenWrt <= 24.10)
    sh install.sh ./podkop-watchdog_*_all.ipk     (any release, incl. apk-based 25.x)
"""

from __future__ import annotations

import gzip
import io
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "files"
EXECUTABLE = {"usr/bin/podkop-watchdog", "etc/init.d/podkop-watchdog"}
PRIVATE = {"etc/config/podkop-watchdog"}  # may hold the Telegram token
CONFFILES = ["/etc/config/podkop-watchdog"]
EPOCH = 1_700_000_000  # reproducible builds

POSTINST = """#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
/etc/init.d/podkop-watchdog enable
/etc/init.d/podkop-watchdog restart
/usr/bin/podkop-watchdog selfcheck || true
exit 0
"""

PRERM = """#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
/etc/init.d/podkop-watchdog stop 2>/dev/null
/etc/init.d/podkop-watchdog disable 2>/dev/null
exit 0
"""


def version() -> str:
    return (FILES / "usr/lib/podkop-watchdog/VERSION").read_text().strip()


def add(tar: tarfile.TarFile, name: str, data: bytes, mode: int, is_dir: bool = False) -> None:
    info = tarfile.TarInfo(name)
    info.mtime = EPOCH
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mode = mode
    if is_dir:
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    else:
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))


def targz(build) -> bytes:
    raw = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=EPOCH) as gz,
        tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tar,
    ):
        build(tar)
    return raw.getvalue()


def data_tar() -> bytes:
    def build(tar: tarfile.TarFile) -> None:
        dirs: set[str] = set()
        for path in sorted(p for p in FILES.rglob("*") if p.is_file()):
            rel = path.relative_to(FILES).as_posix()
            if any(part.startswith(".") for part in rel.split("/")):
                continue  # editor / OS litter such as .DS_Store
            for parent in reversed(Path(rel).parents):
                d = parent.as_posix()
                if d != "." and d not in dirs:
                    dirs.add(d)
                    add(tar, f"./{d}", b"", 0o755, is_dir=True)
            mode = 0o755 if rel in EXECUTABLE else 0o600 if rel in PRIVATE else 0o644
            add(tar, f"./{rel}", path.read_bytes(), mode)

    return targz(build)


def control_tar(size_hint: int) -> bytes:
    control = (
        "Package: podkop-watchdog\n"
        f"Version: {version()}\n"
        "Depends: jq, curl\n"
        "Section: net\n"
        "Architecture: all\n"
        "Maintainer: podkop-watchdog\n"
        f"Installed-Size: {size_hint}\n"
        "Description: Self-healing watchdog for Podkop: router DNS/WAN/Wi-Fi repair, VLESS node failover,\n"
        " Telegram alerts. POSIX shell, no extra dependencies.\n"
    )

    def build(tar: tarfile.TarFile) -> None:
        add(tar, "./control", control.encode(), 0o644)
        add(tar, "./conffiles", ("\n".join(CONFFILES) + "\n").encode(), 0o644)
        add(tar, "./postinst", POSTINST.encode(), 0o755)
        add(tar, "./prerm", PRERM.encode(), 0o755)

    return targz(build)


def build_ipk(outdir: Path) -> Path:
    data = data_tar()
    ctrl = control_tar(sum(p.stat().st_size for p in FILES.rglob("*") if p.is_file()))

    def build(tar: tarfile.TarFile) -> None:
        add(tar, "./debian-binary", b"2.0\n", 0o644)
        add(tar, "./data.tar.gz", data, 0o644)
        add(tar, "./control.tar.gz", ctrl, 0o644)

    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / f"podkop-watchdog_{version()}_all.ipk"
    out.write_bytes(targz(build))  # opkg reads the gzipped-tar flavour of ipk
    return out


if __name__ == "__main__":
    print(build_ipk(Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "dist")))
