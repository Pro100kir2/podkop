"""Stand-in for router commands, driven by world.json in $WD_WORLD_DIR.

Each command is a symlink to this file; behaviour is chosen by argv[0].
Every call is appended to calls.jsonl with the fake clock time.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

WORLD_DIR = Path(os.environ["WD_WORLD_DIR"])
WORLD_FILE = WORLD_DIR / "world.json"


def load() -> dict[str, Any]:
    return json.loads(WORLD_FILE.read_text())


def save(world: dict[str, Any]) -> None:
    tmp = WORLD_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(world))
    tmp.replace(WORLD_FILE)


def now() -> float:
    return float((WORLD_DIR / "uptime").read_text().split()[0])


def record(cmd: str, args: list[str], **extra: Any) -> None:
    with (WORLD_DIR / "calls.jsonl").open("a") as f:
        f.write(json.dumps({"cmd": cmd, "args": args, "t": now(), **extra}) + "\n")


def host_of(url: str) -> str:
    rest = url.split("@", 1)[1] if "@" in url else url
    return re.split(r"[:/?#]", rest, maxsplit=1)[0]


def node(world: dict[str, Any], host: str) -> dict[str, bool]:
    return world["nodes"].get(host, {"isolated": False, "live": False})


def active_live(world: dict[str, Any]) -> bool:
    active = world.get("active") or ""
    return bool(active) and node(world, host_of(active))["live"]


# --------------------------------------------------------------- commands ---


def cmd_logger(args: list[str]) -> int:
    msg = args[args.index("--") + 1 :] if "--" in args else args[-1:]
    with (WORLD_DIR / "logs.txt").open("a") as f:
        f.write(" ".join(msg) + "\n")
    return 0


def cmd_uci(args: list[str]) -> int:
    args = [a for a in args if a != "-q"]
    world = load()
    committed: dict[str, str] = world["uci"]
    staged: dict[str, str | None] = world["staged"]
    op = args[0]
    if op == "show":
        prefix = args[1]
        for key, val in world["wd_config"].items():
            vals = val if isinstance(val, list) else [val]
            print(f"{prefix}.{key}=" + " ".join(f"'{v}'" for v in vals))
        return 0
    if op == "get":
        key = args[1]
        val = staged[key] if key in staged else committed.get(key)
        if val is None:
            return 1
        print(val)
        return 0
    if op == "set":
        key, _, val = args[1].partition("=")
        staged[key] = val
        save(world)
        record("uci", args)
        return 0
    if op == "commit":
        record("uci", args)
        if world.get("uci_commit_fail"):
            return 1
        pkg = args[1] + "."
        for key in [k for k in staged if k.startswith(pkg)]:
            val = staged.pop(key)
            if val is None:
                committed.pop(key, None)
            else:
                committed[key] = val
        save(world)
        return 0
    if op == "changes":
        pkg = args[1] + "."
        for key, val in staged.items():
            if key.startswith(pkg):
                print(f"{key}='{val}'")
        return 0
    if op == "revert":
        staged.pop(args[1], None)
        save(world)
        return 0
    return 1


def cmd_podkop_init(args: list[str]) -> int:
    world = load()
    action = args[0]
    if action == "enabled":
        return 0 if world["podkop_enabled"] else 1
    record("podkop-init", args)
    if action in ("reload", "restart", "start"):
        rcs = world.get("reload_rcs") or []
        if rcs:
            rc = int(rcs.pop(0))
            save(world)
            if rc:
                return rc
        world["active"] = world["uci"].get("podkop.main.proxy_string", "")
        if world.get("reload_revives"):  # a stuck sing-box: the node itself is fine
            n = node(world, host_of(world["active"]))
            n["live"] = n["isolated"]
            world["nodes"][host_of(world["active"])] = n
        if world.get("reload_fixes", True):
            world["singbox"] = True
            world["nft"] = True
            world["dns"]["127.0.0.1"] = True
        save(world)
    return 0


def cmd_ubus(args: list[str]) -> int:
    world = load()
    obj, method = args[1], args[2]
    if obj == "network.interface.lan":
        print(json.dumps({"ipv4-address": [{"address": "192.168.1.1"}]}))
        return 0
    if obj != "network.interface.wan":
        return 4  # UBUS_STATUS_NOT_FOUND
    if method in ("down", "up"):
        record("ifctl", [method])
        world["wan_autostart"] = method == "up"
        if method == "down":
            world["wan_up"] = False
        elif world.get("wan_restart_fixes"):
            world["wan_up"] = True
            world["internet"] = True
        save(world)
        return 0
    status: dict[str, Any] = {"up": world["wan_up"], "autostart": world.get("wan_autostart", True)}
    if world["wan_up"]:
        status["l3_device"] = "pppoe-wan"
    print(json.dumps(status))
    return 0


def cmd_ping(args: list[str]) -> int:
    world = load()
    return 0 if world["wan_up"] and world["internet"] and not world.get("icmp_blocked") else 1


def cmd_nslookup(args: list[str]) -> int:
    world = load()
    name, server = args[-2], args[-1]
    if not (world["wan_up"] and world["internet"]) or not world["dns"].get(server, False):
        print(";; connection timed out; no servers could be reached")
        return 1
    print(f"Server:\t\t{server}\nAddress:\t{server}:53\n\nNon-authoritative answer:")
    print(f"Name:\t{name}\nAddress: 158.160.189.146\n")
    return 0


def cmd_pidof(args: list[str]) -> int:
    world = load()
    if args[-1] == "dnsmasq":
        return 0 if world.get("dnsmasq", True) else 1
    return 0 if world["singbox"] else 1


def cmd_dnsmasq_init(args: list[str]) -> int:
    world = load()
    record("dnsmasq-init", args)
    world["dnsmasq"] = True
    if world.get("dnsmasq_restart_fixes", True):
        world["dns"]["127.0.0.1"] = True
    save(world)
    return 0


def cmd_nft(args: list[str]) -> int:
    return 0 if load()["nft"] else 1


def cmd_flock(args: list[str]) -> int:
    fd = int(args[-1])
    flags = fcntl.LOCK_EX | (fcntl.LOCK_NB if "-n" in args else 0)
    try:
        fcntl.flock(fd, flags)
    except OSError:
        return 1
    return 0


def cmd_sing_box(args: list[str]) -> int:
    world = load()
    cfg_path = args[args.index("-c") + 1]
    try:
        cfg = json.loads(Path(cfg_path).read_text())
        out = cfg["outbounds"][0]
        host = out["server"]
        assert out["routing_mark"] == 2097152
        assert cfg["route"]["default_domain_resolver"] == "wd-dns"
    except Exception:  # noqa: BLE001 - any malformed config is a failed check
        return 1
    if args[0] == "check":
        return 0
    # tools fetch
    record("sing-box-fetch", [host])
    if world["wan_up"] and world["internet"] and node(world, host)["isolated"]:
        print("fl=1f1\nh=www.cloudflare.com\nip=203.0.113.9\n")
        return 0
    print('FATAL Get "https://www.cloudflare.com/cdn-cgi/trace": EOF', file=sys.stderr)
    return 1


VALUE_FLAGS = {
    "-m",
    "-o",
    "-D",
    "-w",
    "-H",
    "-X",
    "--data",
    "--data-urlencode",
    "--resolve",
    "--connect-timeout",
    "--max-time",
    "--max-filesize",
    "--proto",
}


def cmd_curl(args: list[str]) -> int:
    world = load()
    opts: dict[str, list[str]] = {}
    url = ""
    i = 0
    while i < len(args):
        a = args[i]
        if a in VALUE_FLAGS:
            opts.setdefault(a, []).append(args[i + 1])
            i += 2
            continue
        if not a.startswith("-"):
            url = a
        i += 1
    out_file = opts.get("-o", [None])[0]
    hdr_file = opts.get("-D", [None])[0]
    want_code = "-w" in opts

    def reply(code: int, body: str, rc: int = 0, headers: dict[str, str] | None = None) -> int:
        if rc:
            if want_code:
                sys.stdout.write("000")
            return rc
        if out_file:
            Path(out_file).write_text(body)
        elif not want_code:
            sys.stdout.write(body)
        if hdr_file:
            lines = [f"HTTP/2 {code}"] + [f"{k}: {v}" for k, v in (headers or {}).items()]
            Path(hdr_file).write_text("\r\n".join(lines) + "\r\n\r\n")
        if want_code:
            sys.stdout.write(str(code))
        return 0

    parts = urlsplit(url)
    if parts.scheme == "http" and "/proxies/" in parts.path:
        record("clash", [parts.path])
        if not world.get("clash_reachable", True) or not world["singbox"]:
            return reply(0, "", rc=7)
        if parts.path != "/proxies/main-out/delay":
            return reply(404, '{"message":"Resource not found"}')
        if active_live(world) and world["wan_up"] and world["internet"]:
            return reply(200, '{"delay":120}')
        return reply(504, '{"message":"Timeout"}')

    if url.startswith("https://ip.podkop.fyi"):
        record("fullpath", [parts.path])
        if parts.path != "/check":
            return reply(404, "404 Not Found")  # like the real server
        ok = (
            world["wan_up"]
            and world["internet"]
            and world["dns"].get("127.0.0.1")
            and world["nft"]
            and active_live(world)
            and not world.get("path_broken")
        )
        if ok:
            return reply(200, '{"fakeip": true, "IP": "203.0.113.5"}')
        return reply(0, "", rc=28)

    base = "https://api.scat-search.ru/api"
    if url.startswith(base):
        assert "--proto" in opts and opts["--proto"] == ["=https"], "API calls must be https-only"
        assert "-k" not in args and "--insecure" not in args
        method = opts.get("-X", ["POST" if "--data" in opts else "GET"])[0]
        path = urlsplit(url).path[len("/api") :]
        key = f"{method} {path}"
        record("api", [key], query=parts.query, resolve=opts.get("--resolve", []))
        if not (world["wan_up"] and world["internet"]):
            return reply(0, "", rc=6)
        queue = world["api"].get(key)
        if not queue:
            return reply(404, '{"detail":"Not Found"}')
        resp = queue[0]
        if len(queue) > 1:
            queue.pop(0)
            save(world)
        return reply(resp.get("code", 200), resp.get("body", ""), resp.get("rc", 0), resp.get("headers"))

    return reply(0, "", rc=6)


COMMANDS = {
    "logger": cmd_logger,
    "uci": cmd_uci,
    "podkop-init": cmd_podkop_init,
    "dnsmasq-init": cmd_dnsmasq_init,
    "ubus": cmd_ubus,
    "ping": cmd_ping,
    "nslookup": cmd_nslookup,
    "pidof": cmd_pidof,
    "nft": cmd_nft,
    "flock": cmd_flock,
    "sing-box": cmd_sing_box,
    "curl": cmd_curl,
}


def main() -> int:
    name = os.path.basename(sys.argv[0])
    return COMMANDS[name](sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
