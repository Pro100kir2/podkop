# podkop-watchdog: design notes

## 1. Reconnaissance (router 192.168.1.1, read-only, 2026-10-26)

| Item | Observed |
|---|---|
| Firmware | OpenWrt 24.10.5 r29087, target ramips/mt7621, arch mipsel_24kc, kernel 6.6.119 |
| CPU / RAM | MT7621 (MIPS 1004Kc), 119 MB total, **~17 MB available**, no swap |
| Storage | overlay 96.5 MB, 66.8 MB free (UBI) |
| Runtimes | **no Python, no Lua**; busybox 1.36.1 ash, `ucode`, `jq 1.8.1`, `jsonfilter`, `curl 8.12.1` (mbedtls + `ca-bundle`), `flock`, `base64`, `md5sum`, `nslookup`, `ping`, `nft`, `ip`. **No `timeout` or `cksum`**, `sleep` is integer-only |
| Podkop | `podkop v0.7.14-r1` + `luci-app-podkop`, sing-box `1.12.17` |
| Podkop mode | section `main`: `connection_type=proxy`, `proxy_config_type=url`, single `proxy_string` (vless), community list `russia_inside` → **selective routing**: only listed domains go through VLESS, everything else is direct |
| DNS | dnsmasq → `127.0.0.42` (sing-box `dns-in`), sing-box upstream `8.8.8.8/udp`, bootstrap `77.88.8.8`, fakeip `198.18.0.0/15` |
| Routing | nft table `inet PodkopTable`; LAN (`br-lan`) and router-originated (`mangle_output`) TCP/UDP to fakeip range or `podkop_subnets` → mark `0x100000` → `ip rule 105` → table `podkop` → tproxy `127.0.0.1:1602`. Packets with mark `0x200000` bypass `mangle_output`. `podkop_subnets` is currently empty |
| WAN | `wan` = PPPoE (`pppoe-wan`), CGNAT gateway `100.64.0.1` |
| Clash API | sing-box `experimental.clash_api` on `<LAN IP>:9090`, **no secret** (enable_yacd=0) |
| Existing watchdogs | none (no watchcat, no podkop health cron). Cron: `13 9 * * * podkop list_update` |
| Other services | `scat-probe` (procd, ~7.7 MB RSS) — unrelated, untouched |
| sing-box RSS | 21 MB running instance. A one-shot `sing-box tools fetch` peaks at ~20 MB RSS but only **~4.8 MB anonymous** (binary pages are shared). `GOMEMLIMIT` does not change it |
| Live state at recon time | **the active VLESS node was dead**: Clash `/proxies/main-out/delay` → `{"message":"Timeout"}`, sing-box log `dial tcp …:443: i/o timeout`, while direct WAN, fakeip DNS and API all worked |

A backup of `/etc/config/{podkop,dhcp,network,firewall,sing-box}` and
`/etc/sing-box/config.json` was taken **on the router** at
`/root/podkop-watchdog-backup-20261026-221757/` (mode 0600; credentials never left the router).

### Language choice

Python is not installed and would cost several MB of the ~17 MB free RAM plus
~10 MB flash. Lua is absent. The service is therefore **POSIX shell (busybox
ash)** using only tools already present (`curl`, `jq`, `uci`, `ubus`, `nft`,
`sing-box`). Tests are written in Python/pytest on the development machine and
drive the real shell script against stubbed system commands.

## 2. Verified contracts

### Scat API (source: `vpn/scat/app/api/routes.py` + live requests)

All under `https://api.scat-search.ru/api`. TLS verified (curl default CA bundle).

| Endpoint | Method | Response | Notes |
|---|---|---|---|
| `/health` | GET | `200 {"status":"ok"}` | used for API reachability |
| `/vless/sub` | GET | `200 text/plain`, **base64** of newline-separated `vless://` links by default; `?format=raw` gives plain text; `?rename=false` keeps original names; `limit` is capped server-side by `TOP_COUNT=5` | headers `Profile-Update-Interval: 24`, `Subscription-Userinfo` |
| `/scan` | POST, no body | `200 {"outcome": "cached\|started\|joined\|cooldown\|busy", "cache_state", "is_scanning", "queued", "progress", "last_scan_failed", "cache"}` | **asynchronous**: returns immediately; a scan runs only if cache is stale. Per-IP limit `6/min` → `429` + `Retry-After`. `GET` → `405` |
| `/cache/refresh` | POST, no body | `200 {"outcome", "retry_after": 600, ...status}` | **asynchronous** forced rescan; global cooldown `REFRESH_COOLDOWN_SECONDS=600` → `429 {"detail": "Results were refreshed recently"}` + `Retry-After`. `GET` → `405` |
| `/scan/status` | GET | `{"cache_state","is_scanning","queued","progress","last_scan_failed","cache":{...}}` | polled after scan/refresh; a scan takes ~80 s |

### Podkop integration (source: `/usr/bin/podkop`, `/usr/lib/podkop/*.sh` v0.7.14)

* Supported lifecycle: `uci set podkop.<section>.proxy_string=…` → `uci commit podkop`
  → `/etc/init.d/podkop reload`. `reload` = `stop_main`+`start_main`: rebuilds
  the sing-box JSON (validated with `sing-box check` and written atomically via
  `mv`, only if the hash changed), recreates nft rules, restarts sing-box. It
  does **not** touch dnsmasq (`restart` does).
* `uci commit` alone does not trigger Podkop (its procd trigger needs `reload_config`).
* `podkop.settings.shutdown_correctly=1` means Podkop was stopped on purpose.
* URL → outbound conversion: `sing_box_cf_add_proxy_outbound` in
  `/usr/lib/podkop/sing_box_config_facade.sh`. The watchdog **reuses it** so a
  candidate is tested with exactly the outbound Podkop would generate. The
  library is **not `set -u` safe** (verified: it fails on `$6` unset).
* Built-in tunnel probes: route rule `ip.podkop.fyi → main-out`
  (full path: fakeip DNS + nft + tproxy + tunnel), and Clash API
  `GET /proxies/<tag>/delay?url=…&timeout=…` (tunnel only).

## 3. Design

One procd service, one process, one lock (`flock`). The main loop calls
`tick`, which runs **one bounded step** of a persisted state machine and
returns how long to sleep. No step sleeps internally; long waits are states.

### Diagnostics (each tick in MONITOR)

| Check | How | Failure means |
|---|---|---|
| WAN link | `ubus call network.interface.<wan> status` → `.up` | WAN_DOWN |
| Internet | ICMP to several IP literals (default 77.88.8.8, 1.1.1.1, 8.8.8.8), any success = up | WAN_DOWN (ISP) |
| Podkop intent | `/etc/init.d/podkop enabled` and `shutdown_correctly != 1` | PODKOP_OFF → hands off |
| Podkop running | `pidof sing-box` + `nft list table inet PodkopTable` | PODKOP_DOWN |
| DNS | `nslookup` via 127.0.0.1 (dnsmasq→sing-box), via Podkop's `dns_server`, via a direct resolver | DNS_CHAIN_DOWN (local broken, upstream fine) / DNS_UPSTREAM_DOWN |
| Tunnel (node) | Clash API delay test of `<section>-out` | TUNNEL_DOWN → failover |
| Full path | `curl https://ip.podkop.fyi/check` (JSON `IP` field; same endpoint Podkop's LuCI uses, root URL is 404) | PATH_DOWN — report only, third-party dependency |
| API | `GET /health` every `api_check_interval` and during recovery | reported only |

Precedence: PODKOP_OFF > WAN_DOWN > PODKOP_DOWN > DNS_UPSTREAM_DOWN > TUNNEL_DOWN > DNS_CHAIN_DOWN > PATH_DOWN > HEALTHY.
(A dead sing-box is restarted even if upstream DNS is also down; upstream DNS
is only probed when local resolution fails.)
Only TUNNEL_DOWN triggers node failover. PODKOP_DOWN / DNS_CHAIN_DOWN
trigger a rate-limited `podkop reload`. PATH_DOWN is report-only. Everything else just waits.

### Recovery state machine

```
MONITOR --tunnel fails N times--> [LKG test] --> FETCH --> TEST --(pass)--> APPLY --> VERIFY --(ok)--> COMMIT --> MONITOR
                                                    ^         |                         |
                                                    |         | none left               | fails
                                                    |         v                         v
                                                    |   phase: lkg     -> FETCH      ROLLBACK -> TEST next
                                                    |          initial -> SCAN -> SCAN_WAIT -> FETCH
                                                    |          scan    -> REFRESH -> SCAN_WAIT -> FETCH
                                                    +--------- refresh -> REFRESH_WAIT (until last refresh + 600 s) -> REFRESH ...
```

* Candidates are tested **in isolation**: a short-lived `sing-box tools fetch`
  with a minimal config (only the candidate outbound, its own direct DNS
  resolver, `routing_mark 0x200000` so Podkop's nft rules cannot capture it),
  `oom_score_adj=1000`, a kill timer and a free-memory guard. The live
  connection is not touched. A pass requires the real HTTPS body to match
  (`h=www.cloudflare.com` from `/cdn-cgi/trace`) `candidate_test_passes` times.
* APPLY saves the pre-recovery `proxy_string` (rollback copy, tmpfs, 0600),
  refuses to run if `uci changes podkop` shows someone's uncommitted edits,
  respects the restart budget, then uses the Podkop lifecycle above.
* VERIFY uses the Clash API tunnel test through the real Podkop instance
  (full path only as a fallback when the Clash API is unavailable). WAN loss during VERIFY pauses it instead of counting as failure.
* COMMIT stores the new last-known-good (LKG) atomically
  (`/etc/podkop-watchdog/lkg`, 0600, written only when it changes).
* All API/fetch/test states first check WAN (pause if down) and whether the
  current node came back by itself (abort recovery after `tunnel_ok_threshold`).
* API errors: curl errors/5xx/429 are retried `api_retries` times with
  exponential backoff (`Retry-After` honoured, capped), then the machine moves
  to the next phase. In a full API outage the cycle settles at one refresh +
  one subscription attempt per `refresh_interval` (600 s, enforced minimum).

### Safety properties

* State is written before every side effect (APPLYING), so a crash during an
  apply resumes in VERIFY and rolls back if needed; `NEXT_AT` is persisted so a
  crash loop cannot burst API calls or restarts.
* Restart budget (`restart_min_interval`, `restart_max_per_hour`) covers
  health restarts and applies. Rollbacks are never blocked by the budget.
* Recovery traffic: API host is resolved through a direct DNS server (not the
  possibly broken sing-box DNS) and pinned with `curl --resolve`; answers in
  the fakeip range are rejected. Candidate tests set `routing_mark` to bypass
  Podkop marks. The watchdog never edits firewall, DNS, routes, or Podkop's
  generated files.
* Input from the API is untrusted: size cap (256 KiB), strict `vless://`
  regex (UUID user, host, port 1–65535, URL-safe charset without quotes,
  `$`, backslash, backtick or whitespace), dedupe, `max_candidates` cap,
  `sing-box check` before use. No `eval`.
* Secrets: node identity in logs is `id=<first 8 hex of md5(URL)>`; URLs, UUIDs,
  hostnames and keys are never logged. Candidate list lives in tmpfs (0700
  dir, 0600 files) and is deleted when recovery ends.

## 4. Assumptions and open points

* The Clash API stays enabled by Podkop (it is in v0.7.14 regardless of YACD).
  If it is unreachable the watchdog falls back to the full-path check.
* Only `proxy_config_type=url` is managed. For `selector`, `urltest` or
  `outbound` modes the watchdog only monitors and restarts Podkop on plumbing
  failures; it never rewrites those configs.
* If Podkop's sing-box resolves VLESS hostnames through an upstream that is
  blocked, a candidate can pass in isolation and fail after apply; VERIFY
  catches this and rolls back, and `max_applies_per_round` bounds the churn.
* `podkop reload` is not killed on timeout: interrupting it mid-way could leave
  nft/sing-box half configured.

## 5. First live run (2026-10-27)

* Run 1 exposed two defects, fixed and covered by tests:
  1. the full-path probe used `https://ip.podkop.fyi` (404); Podkop's LuCI uses
     `/check`, which returns `{"fakeip":..,"IP":".."}` — every switch was rolled back;
  2. a 5 s tunnel timeout was too tight: measured fetches through a working node
     took 1.9–5.7 s on this MT7621 (incl. ~1.5 s sing-box start-up), more while
     Podkop's post-reload `list_update` runs. Now 8 s, settle 20 s, 4×15 s verify.
  Also found: busybox has no `cksum` and its `flock` has no `-w`.
  The rollbacks, restart budget (6/h) and 10-minute refresh cycle all behaved as
  designed during that run; LAN internet stayed up.
* Run 2: dead node detected after 3 checks, `dd33449e` passed in isolation,
  applied, verified through Podkop; recovery took 80 s with one switch. Tunnel
  exit IP differs from the direct WAN IP.
