# podkop-watchdog

Autonomous recovery service for OpenWrt routers running
[Podkop](https://github.com/itdoginfo/podkop). It monitors WAN, DNS, Podkop
and the active VLESS tunnel, tells apart ISP/DNS/API outages from a broken
node, and, only when the node itself is broken, picks a working VLESS
node from the Scat API, applies it through Podkop's normal lifecycle,
verifies it, and rolls back if verification fails.

* POSIX shell for busybox ash, ~1.2k lines. No Python, no new packages: uses
  `curl`, `jq`, `uci`, `ubus`, `nft`, `sing-box` already present with Podkop.
* procd service with respawn, single-instance lock, persisted state machine.
* Built and verified against OpenWrt 24.10.5 / Podkop v0.7.14 / sing-box 1.12.17
  (see [docs/DESIGN.md](docs/DESIGN.md) for the reconnaissance and contracts).

## Layout

```
files/                              -> copied to / on the router
  usr/bin/podkop-watchdog           CLI: run | tick | status | diagnose | test-candidates
  usr/lib/podkop-watchdog/
    common.sh                       config, state file, clock, locks, restart budget
    checks.sh                       read-only diagnostics and classification
    api.sh                          Scat API client, subscription validation
    candidate.sh                    isolated node tests, uci/Podkop apply, LKG
    machine.sh                      recovery state machine (one step per tick)
  etc/init.d/podkop-watchdog        procd init script
  etc/config/podkop-watchdog        UCI config, every option documented
  lib/upgrade/keep.d/podkop-watchdog  keeps the LKG across sysupgrade
scripts/deploy.sh, scripts/uninstall.sh
tests/                              pytest suite (runs the real shell code)
docs/DESIGN.md                      recon results, contracts, design, assumptions
```

## How it decides

Every `check_interval` (30 s) the service classifies the router:

| Class | Meaning | Action |
|---|---|---|
| `PODKOP_OFF` | Podkop disabled or stopped on purpose (`shutdown_correctly=1`) | none |
| `WAN_DOWN` | WAN link down or no direct internet target answers | none (logged once) |
| `PODKOP_DOWN` | sing-box not running or `PodkopTable` missing | `podkop reload` after 3 checks, budgeted |
| `DNS_UPSTREAM_DOWN` | local DNS fails and Podkop's upstream resolver is unreachable | none |
| `TUNNEL_DOWN` | real HTTP test through the active outbound (Clash API) fails | node failover after 3 checks |
| `DNS_CHAIN_DOWN` | dnsmasq → sing-box DNS broken, upstream fine | `podkop reload`, budgeted |
| `PATH_DOWN` | node works but the fakeip/nft/tproxy path probe (`ip.podkop.fyi/check`, third-party) fails | none (logged once) |
| `HEALTHY` | all good | records current node as last-known-good |

## Recovery state machine

```
MONITOR ──TUNNEL_DOWN ×3──▶ (LKG first, if different from current)
   ▲                           │
   │                     FETCH /vless/sub ──▶ TEST (isolated sing-box, one node per tick)
   │                           ▲                  │ pass                 │ none left
   │                           │                  ▼                      ▼
   │                           │               APPLY (uci + podkop reload, budgeted)
   │                           │                  ▼                 phase lkg     → FETCH
   └──── COMMIT (save LKG) ◀── VERIFY ──fail──▶ ROLLBACK ─▶ TEST   phase initial → SCAN → [SCAN_WAIT] → FETCH
                                                                   phase scan    → REFRESH → [SCAN_WAIT] → FETCH
                                                                   phase refresh → REFRESH_WAIT (600 s after last refresh) → REFRESH …
```

* `POST /scan` and `POST /cache/refresh` are asynchronous on the server; the
  service polls `GET /scan/status` until `is_scanning=false` (max 15 min).
* While recovering it re-checks WAN and the active node every `check_interval`:
  WAN loss pauses it (no API calls, no retries spent), and a node that comes
  back by itself (2 good checks) cancels recovery.
* The 10-minute refresh cycle holds during API outages: per cycle at most one
  refresh and one subscription request, each with ≤ 3 attempts (15 s, 30 s
  backoff; `Retry-After` honoured). A server-side 429 cooldown on refresh is
  treated as "someone refreshed recently" and its results are used.
* At most `max_applies_per_round` (3) switches per cycle; a node that fails
  after a switch is not applied again in the same cycle.
* State lives in `/tmp/podkop-watchdog/state` and is written before every
  side effect, so a crash mid-switch resumes in VERIFY (and rolls back if
  needed), and the next-run time survives respawns (no request bursts).

## Install

From the development machine (files only; nothing is enabled):

```bash
scripts/deploy.sh root@192.168.1.1
```

On the router:

```bash
podkop-watchdog diagnose
```

```bash
podkop-watchdog test-candidates
```

```bash
/etc/init.d/podkop-watchdog enable && /etc/init.d/podkop-watchdog start
```

Watch it:

```bash
logread -e podkop-watchdog -f
```

```bash
podkop-watchdog status
```

## Rollback / removal

1. Stop the service (Podkop keeps running with whatever node is configured):

   ```bash
   /etc/init.d/podkop-watchdog stop && /etc/init.d/podkop-watchdog disable
   ```

2. Return Podkop to the configuration from before the watchdog existed, if
   wanted. A backup taken during reconnaissance is on the router at
   `/root/podkop-watchdog-backup-20261026-221757/etc-config.tgz`:

   ```bash
   tar -xzf /root/podkop-watchdog-backup-20261026-221757/etc-config.tgz -O etc/config/podkop > /tmp/podkop.restore && cp /tmp/podkop.restore /etc/config/podkop && rm /tmp/podkop.restore && /etc/init.d/podkop restart
   ```

   (That backup's node was already dead at backup time.)

3. Remove the files: `scripts/uninstall.sh root@192.168.1.1` (add `--purge`
   to also delete the config and stored last-known-good node).

The watchdog only ever changes `podkop.<section>.proxy_string`. It never
touches firewall, DNS, dnsmasq, routes, or Podkop-generated files.

## Tests

```bash
uv sync
```

```bash
uv run pytest -n 8
```

```bash
WD_TEST_SHELL=sh uv run pytest -n 8
```

The suite runs the real shell code with stub router commands (`curl`, `uci`,
`ubus`, `ping`, `nslookup`, `sing-box`, Podkop init…) driven by a JSON world
and a fake clock. Every test also asserts that no UUID, node host or
`vless://` URL reaches the log or state file. The tests prove the state
machine logic; they do **not** prove real VPN connectivity.

## Security notes

* HTTPS only (`--proto =https`, TLS ≥ 1.2, certificate verification always on).
* API host resolved via a direct DNS server and pinned with `--resolve`
  (never through the possibly broken sing-box DNS; fakeip answers rejected).
* Subscription treated as untrusted: 256 KiB cap, strict `vless://` regex
  (UUID user, host, port 1–65535, no quotes/`$`/backtick/backslash/space),
  display names dropped, dedupe, `sing-box check` before use, no `eval`.
* Logs identify nodes only as `id=<8 hex chars of md5>`. Candidate lists live in tmpfs
  (0700/0600) and are deleted when recovery ends. The last-known-good URL is
  kept in `/etc/podkop-watchdog/lkg` (0600) — the same secret Podkop already
  stores in `/etc/config/podkop`; set `persist_lkg 0` to keep it in RAM only.

## Known limitations

* Only `proxy_config_type=url` is managed. `selector`, `urltest` and
  `outbound` modes are monitored but never rewritten.
* Node health relies on Podkop's Clash API (`<LAN IP>:9090`); without it the
  full-path check is used. Note the Clash API has no secret on this router
  and is reachable from the LAN (Podkop default) — not changed by this project.
* A node can pass the isolated test (direct resolver) and still fail in Podkop
  if Podkop's own upstream DNS cannot resolve its hostname; VERIFY rolls back
  and the per-cycle switch limit bounds churn.
* The full-path probe depends on the third-party `ip.podkop.fyi` service, so it is
  report-only; post-switch verification relies on the real tunnel request through
  Podkop's own sing-box (Clash API).
* `podkop reload` is never killed on timeout (killing it could leave nft or
  sing-box half-configured).
* If the user has unsaved LuCI changes to `podkop`, switches wait; a
  rollback in that window would commit those pending changes too (logged).
