"""Harness: runs the real podkop-watchdog shell code against stubbed router commands."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "files"
SCRIPT = FILES / "usr/bin/podkop-watchdog"
LIB = FILES / "usr/lib/podkop-watchdog"
STUB = Path(__file__).with_name("stub.py")
# Fake but well-formed bot token; must never show up anywhere but the request.
TG_TOKEN = "123456789:AAFakeTokenForTestsOnly_abcdefghijk"
SHELL = os.environ.get("WD_TEST_SHELL", "dash")

STUB_COMMANDS = [
    "logger",
    "uci",
    "podkop-init",
    "dnsmasq-init",
    "ubus",
    "ping",
    "nslookup",
    "pidof",
    "nft",
    "flock",
    "sing-box",
    "curl",
]

# Minimal replacement for Podkop's URL parser: emits {"outbounds":[...]} like
# sing_box_cf_add_proxy_outbound does, using the tag "<section>-out".
FACADE_STUB = r"""
sing_box_cf_add_proxy_outbound() {
    _hp=${3#*@}; _hp=${_hp%%[/?#]*}
    _host=${_hp%:*}; _port=${_hp##*:}
    case "$_host" in *badparse*) exit 1 ;; esac
    jq -nc --arg t "$2-out" --arg h "$_host" --argjson p "$_port" \
        '{outbounds: [{type: "vless", tag: $t, server: $h, server_port: $p, uuid: "x"}]}'
}
"""


def vless(host: str, name: str = "node") -> str:
    return (
        f"vless://{uuid.uuid4()}@{host}:443?encryption=none&security=reality"
        f"&type=tcp&flow=xtls-rprx-vision&sni=example.org#{name}"
    )


def sub_body(*urls: str, b64: bool = False) -> str:
    text = "".join(u + "\n" for u in urls)
    return base64.b64encode(text.encode()).decode() if b64 else text


def resp(
    code: int = 200, body: Any = "", rc: int = 0, headers: dict[str, str] | None = None
) -> dict[str, Any]:
    if not isinstance(body, str):
        body = json.dumps(body)
    out: dict[str, Any] = {"code": code, "body": body, "rc": rc}
    if headers:
        out["headers"] = headers
    return out


def status_body(scanning: bool = False) -> dict[str, Any]:
    return {
        "cache_state": "fresh",
        "is_scanning": scanning,
        "queued": False,
        "progress": None,
        "last_scan_failed": False,
        "cache": None,
    }


class Router:
    """A fake router: world.json + fake uptime + sandboxed state dirs."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.bin = base / "bin"
        self.bin.mkdir()
        python = sys.executable
        stub_src = STUB.read_text()
        stub = self.bin / "_stub.py"
        stub.write_text(f"#!{python} -S\n" + stub_src)
        stub.chmod(0o755)
        for name in STUB_COMMANDS:
            (self.bin / name).symlink_to(stub)
        self.podkop_lib = base / "podkop-lib"
        self.podkop_lib.mkdir()
        (self.podkop_lib / "sing_box_config_facade.sh").write_text(FACADE_STUB)
        self.state_dir = base / "tmp/podkop-watchdog"
        self.persist_dir = base / "etc/podkop-watchdog"
        self.lock = base / "lock"
        self.meminfo = base / "meminfo"
        self.set_mem(60000)
        self.urls = {h: vless(h, h) for h in ("a.example", "b.example", "c.example", "d.example")}
        self.world: dict[str, Any] = {
            "wan_up": True,
            "internet": True,
            "dns": {"127.0.0.1": True, "8.8.8.8": True, "77.88.8.8": True},
            "singbox": True,
            "nft": True,
            "podkop_enabled": True,
            "clash_reachable": True,
            "uci": {
                "podkop.settings.shutdown_correctly": "0",
                "podkop.settings.dns_type": "udp",
                "podkop.settings.dns_server": "8.8.8.8",
                "podkop.settings.bootstrap_dns_server": "77.88.8.8",
                "podkop.main.connection_type": "proxy",
                "podkop.main.proxy_config_type": "url",
                "podkop.main.proxy_string": self.urls["a.example"],
            },
            "staged": {},
            "wd_config": {},
            "active": self.urls["a.example"],
            "nodes": {"a.example": {"isolated": True, "live": True}},
            "api": {
                "GET /health": [resp(body={"status": "ok"})],
                "GET /scan/status": [resp(body=status_body(False))],
            },
        }
        self.save()
        (self.base / "hostname").write_text("TestRouter\n")
        self.set_time(1000)

    # ----------------------------------------------------------- world ---
    def save(self) -> None:
        (self.base / "world.json").write_text(json.dumps(self.world))

    def load(self) -> dict[str, Any]:
        self.world = json.loads((self.base / "world.json").read_text())
        return self.world

    def update(self, fn: Callable[[dict[str, Any]], None]) -> None:
        self.load()
        fn(self.world)
        self.save()

    def set_node(self, host: str, isolated: bool, live: bool | None = None) -> None:
        self.update(
            lambda w: w["nodes"].__setitem__(
                host, {"isolated": isolated, "live": isolated if live is None else live}
            )
        )

    def set_api(self, key: str, *responses: dict[str, Any]) -> None:
        self.update(lambda w: w["api"].__setitem__(key, list(responses)))

    def set_config(self, **opts: Any) -> None:
        self.update(lambda w: w["wd_config"].update({k: v for k, v in opts.items()}))

    def set_mem(self, kb: int) -> None:
        self.meminfo.write_text(f"MemTotal: 119244 kB\nMemAvailable: {kb} kB\n")

    def set_rx(self, rx_bytes: int) -> None:
        """WAN receive counter as the kernel exposes it in sysfs."""
        f = self.base / "sysnet/pppoe-wan/statistics/rx_bytes"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"{rx_bytes}\n")

    def set_tx(self, ifname: str, packets: int) -> None:
        f = self.base / f"sysnet/{ifname}/statistics/tx_packets"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"{packets}\n")

    def telegrams(self) -> list[dict[str, Any]]:
        """Every delivery attempt: {"text", "via", "t"}."""
        return self.calls("telegram")

    def events(self) -> str:
        f = self.persist_dir / "events.log"
        return f.read_text() if f.exists() else ""

    def wan_restarts(self) -> list[dict[str, Any]]:
        return [c for c in self.calls("ifctl") if c["args"][0] == "up"]

    # ----------------------------------------------------------- clock ---
    def set_time(self, t: int) -> None:
        self.now = t
        (self.base / "uptime").write_text(f"{t}.50 0.00\n")

    # ------------------------------------------------------------- run ---
    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{self.bin}:{env['PATH']}",
                "WD_WORLD_DIR": str(self.base),
                "WD_LIB_DIR": str(LIB),
                "WD_STATE_DIR": str(self.state_dir),
                "WD_PERSIST_DIR": str(self.persist_dir),
                "WD_LOCK_FILE": str(self.lock),
                "WD_UPTIME_FILE": str(self.base / "uptime"),
                "WD_MEMINFO_FILE": str(self.meminfo),
                "WD_PODKOP_INIT": str(self.bin / "podkop-init"),
                "WD_PODKOP_LIB": str(self.podkop_lib),
                "WD_DNSMASQ_INIT": str(self.bin / "dnsmasq-init"),
                "WD_SYS_NET": str(self.base / "sysnet"),
                "WD_EVENT_LOG": str(self.persist_dir / "events.log"),
                "WD_HOSTNAME_FILE": str(self.base / "hostname"),
                "WD_STRICT": "1",
            }
        )
        return env

    def cli(self, *args: str, check: bool = True, timeout: float = 60) -> subprocess.CompletedProcess[str]:
        proc = subprocess.run(
            [SHELL, str(SCRIPT), *args], env=self.env(), capture_output=True, text=True, timeout=timeout
        )
        if check and proc.returncode != 0:
            raise AssertionError(f"{args} rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}")
        assert "parameter not set" not in proc.stderr, proc.stderr
        return proc

    def state(self) -> dict[str, str]:
        f = self.state_dir / "state"
        if not f.exists():
            return {}
        return dict(line.split("=", 1) for line in f.read_text().splitlines() if "=" in line)

    def step(self) -> dict[str, str]:
        """One tick, then jump the clock to the scheduled next tick."""
        self.cli("tick")
        st = self.state()
        self.set_time(max(self.now, int(st.get("NEXT_AT", self.now))))
        return st

    def run_until(self, pred: Callable[[dict[str, str]], bool], max_steps: int = 80) -> dict[str, str]:
        for _ in range(max_steps):
            st = self.step()
            if pred(st):
                return st
        raise AssertionError(f"condition not reached; state={self.state()}\nlogs:\n{self.logs()}")

    def run_steps(self, n: int) -> dict[str, str]:
        st: dict[str, str] = {}
        for _ in range(n):
            st = self.step()
        return st

    # ------------------------------------------------------- inspection ---
    def calls(self, cmd: str | None = None) -> list[dict[str, Any]]:
        f = self.base / "calls.jsonl"
        if not f.exists():
            return []
        rows = [json.loads(line) for line in f.read_text().splitlines()]
        return [r for r in rows if cmd is None or r["cmd"] == cmd]

    def api_calls(self, key: str | None = None) -> list[dict[str, Any]]:
        return [c for c in self.calls("api") if key is None or c["args"][0] == key]

    def reloads(self) -> list[dict[str, Any]]:
        return [c for c in self.calls("podkop-init") if c["args"][0] in ("reload", "restart")]

    def logs(self) -> str:
        f = self.base / "logs.txt"
        return f.read_text() if f.exists() else ""

    def proxy(self) -> str:
        return self.load()["uci"]["podkop.main.proxy_string"]

    def lkg(self) -> str | None:
        f = self.persist_dir / "lkg"
        return f.read_text().strip() if f.exists() else None


@pytest.fixture
def router(tmp_path: Path) -> Iterator[Router]:
    if shutil.which(SHELL) is None:
        pytest.skip(f"shell {SHELL} not available")
    r = Router(tmp_path)
    yield r
    # Secrets must never reach logs or the state file.
    logs = r.logs()
    state = (r.state_dir / "state").read_text() if (r.state_dir / "state").exists() else ""
    calls = (r.base / "calls.jsonl").read_text() if (r.base / "calls.jsonl").exists() else ""
    for text in (logs, state, r.events(), calls):
        assert TG_TOKEN not in text, "telegram token leaked"
    for text in (logs, state):
        assert "vless://" not in text
        for url in r.urls.values():
            user = url.split("://", 1)[1].split("@", 1)[0]
            host = url.split("@", 1)[1].split(":", 1)[0]
            assert user not in text, "UUID leaked"
            assert host not in text, "node host leaked"
