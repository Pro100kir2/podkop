"""Recovery state machine: failover, scan/refresh sequence, API errors, untrusted input."""

from __future__ import annotations

import base64

import pytest
from conftest import Router, resp, status_body, sub_body


def bare(url: str) -> str:
    return url.split("#", 1)[0]


def back_to_monitor(r: Router, url: str):
    return lambda st: st["STATE"] == "MONITOR" and r.proxy() == bare(url)


def test_working_active_node_needs_no_action(router: Router) -> None:
    st = router.run_steps(5)
    assert st["STATE"] == "MONITOR"
    assert "class=HEALTHY" in st["D_SUMMARY"]
    assert router.reloads() == []
    assert router.api_calls("GET /vless/sub") == []
    assert len(router.api_calls("GET /health")) == 1  # periodic, not every tick
    assert router.lkg() == router.urls["a.example"]  # current config recorded as known-good


def test_active_node_failure_and_successful_failover(router: Router) -> None:
    u = router.urls
    router.set_node("a.example", False)
    router.set_node("b.example", True)
    router.set_api("GET /vless/sub", resp(body=sub_body(u["a.example"], u["b.example"])))

    # Hysteresis: two failures are not enough.
    st = router.run_steps(2)
    assert st["STATE"] == "MONITOR" and st["FAIL_N"] == "2"

    router.run_until(back_to_monitor(router, u["b.example"]))
    assert len(router.reloads()) == 1
    assert router.lkg() == bare(u["b.example"])
    # The failing active node is not re-tested; b passes twice in isolation.
    # The active node is self-tested once first (a stuck Podkop would be reloaded, not switched).
    assert [c["args"][0] for c in router.calls("sing-box-fetch")] == ["a.example", "b.example", "b.example"]
    assert router.api_calls("POST /scan") == [] and router.api_calls("POST /cache/refresh") == []
    assert "recovery complete" in router.logs()
    # Subscription data is not kept after recovery.
    assert not (router.state_dir / "candidates").exists()
    assert not (router.state_dir / "rollback").exists()


def test_no_working_nodes_then_scan_produces_working_node(router: Router) -> None:
    u = router.urls
    router.set_node("a.example", False)
    router.set_node("b.example", True)
    router.set_api("GET /vless/sub", resp(body=sub_body(u["c.example"])), resp(body=sub_body(u["b.example"])))
    router.set_api("POST /scan", resp(body={"outcome": "started", **status_body(True)}))
    router.set_api("GET /scan/status", resp(body=status_body(True)), resp(body=status_body(False)))

    router.run_until(back_to_monitor(router, u["b.example"]))
    keys = [c["args"][0] for c in router.api_calls() if c["args"][0] != "GET /health"]
    assert keys == ["GET /vless/sub", "POST /scan", "GET /scan/status", "GET /scan/status", "GET /vless/sub"]
    assert router.api_calls("POST /cache/refresh") == []


def test_scan_failure_is_retried_then_cache_refresh_produces_working_node(router: Router) -> None:
    u = router.urls
    router.set_node("a.example", False)
    router.set_node("b.example", True)
    router.set_api(
        "GET /vless/sub",
        resp(body=sub_body(u["c.example"])),
        resp(body=sub_body(u["c.example"])),
        resp(body=sub_body(u["b.example"])),
    )
    router.set_api("POST /scan", resp(500, {"detail": "boom"}))
    router.set_api("POST /cache/refresh", resp(body={"outcome": "started", "retry_after": 600}))
    router.set_api("GET /scan/status", resp(body=status_body(False)))

    router.run_until(back_to_monitor(router, u["b.example"]))
    scans = router.api_calls("POST /scan")
    assert len(scans) == 3  # api_retries
    assert [b["t"] - a["t"] for a, b in zip(scans, scans[1:], strict=False)] == [15, 30]  # backoff
    assert len(router.api_calls("POST /cache/refresh")) == 1
    assert "scan request failed" in router.logs()


def test_cache_refresh_after_cached_scan(router: Router) -> None:
    u = router.urls
    router.set_node("a.example", False)
    router.set_node("d.example", True)
    router.set_api(
        "GET /vless/sub",
        resp(body=sub_body(u["c.example"])),
        resp(body=sub_body(u["c.example"])),
        resp(body=sub_body(u["d.example"])),
    )
    router.set_api("POST /scan", resp(body={"outcome": "cached", **status_body(False)}))
    router.set_api("POST /cache/refresh", resp(body={"outcome": "started", "retry_after": 600}))

    router.run_until(back_to_monitor(router, u["d.example"]))
    keys = [c["args"][0] for c in router.api_calls() if c["args"][0] != "GET /health"]
    assert keys == [
        "GET /vless/sub",
        "POST /scan",
        "GET /vless/sub",
        "POST /cache/refresh",
        "GET /scan/status",
        "GET /vless/sub",
    ]


def test_refresh_repeats_every_10_minutes_until_a_node_works(router: Router) -> None:
    u = router.urls
    router.set_node("a.example", False)
    router.set_api("GET /vless/sub", resp(body=sub_body(u["c.example"])))
    router.set_api("POST /scan", resp(body={"outcome": "cached"}))
    router.set_api("POST /cache/refresh", resp(body={"outcome": "started"}))

    router.run_until(lambda st: len(router.api_calls("POST /cache/refresh")) >= 4, max_steps=400)
    times = [c["t"] for c in router.api_calls("POST /cache/refresh")]
    gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
    assert all(600 <= g <= 600 + 30 for g in gaps), gaps
    # One subscription fetch per refresh cycle: no request bursts.
    subs = [c["t"] for c in router.api_calls("GET /vless/sub")]
    for start, end in zip(times, times[1:], strict=False):
        assert len([t for t in subs if start <= t < end]) == 1
    assert router.reloads() == []  # never restarts Podkop while nothing works

    # A working node shows up: the next cycle picks it up.
    router.set_node("b.example", True)
    router.set_api("GET /vless/sub", resp(body=sub_body(u["b.example"])))
    router.run_until(back_to_monitor(router, u["b.example"]), max_steps=200)


def test_api_outage_keeps_ten_minute_cycle(router: Router) -> None:
    router.set_node("a.example", False)
    for key in ("GET /vless/sub", "POST /scan", "POST /cache/refresh"):
        router.set_api(key, resp(rc=28))  # curl timeout
    start = router.now
    router.run_until(lambda st: router.now - start > 3600, max_steps=1000)
    times = sorted(c["t"] for c in router.api_calls("POST /cache/refresh"))
    # A cycle = first attempt + its retries (15 s, 30 s later); cycles start >= 600 s apart.
    firsts = [t for i, t in enumerate(times) if i == 0 or t - times[i - 1] > 120]
    assert 5 <= len(firsts) <= 7, firsts
    assert all(600 <= b - a <= 630 for a, b in zip(firsts, firsts[1:], strict=False)), firsts
    assert len(times) == 3 * len(firsts) or len(times) == 3 * len(firsts) - 2  # last cycle may be cut
    assert len(router.api_calls()) < 80  # bounded: ~13 requests per 10 minutes at most
    assert router.reloads() == []


@pytest.mark.parametrize("failure", [resp(rc=28), resp(503, "busy"), resp(rc=7)])
def test_api_timeout_and_http_errors_are_retried_with_backoff(router: Router, failure) -> None:
    u = router.urls
    router.set_node("a.example", False)
    router.set_node("b.example", True)
    router.set_api("GET /vless/sub", failure, failure, resp(body=sub_body(u["b.example"])))
    router.run_until(back_to_monitor(router, u["b.example"]))
    subs = router.api_calls("GET /vless/sub")
    assert [b["t"] - a["t"] for a, b in zip(subs, subs[1:], strict=False)] == [15, 30]


def test_retry_after_is_honoured(router: Router) -> None:
    u = router.urls
    router.set_node("a.example", False)
    router.set_node("b.example", True)
    router.set_api(
        "GET /vless/sub",
        resp(429, {"detail": "slow down"}, headers={"Retry-After": "120"}),
        resp(body=sub_body(u["b.example"])),
    )
    router.run_until(back_to_monitor(router, u["b.example"]))
    subs = router.api_calls("GET /vless/sub")
    assert subs[1]["t"] - subs[0]["t"] == 120


def test_refresh_cooldown_429_uses_current_results(router: Router) -> None:
    u = router.urls
    router.set_node("a.example", False)
    router.set_node("b.example", True)
    router.set_api(
        "GET /vless/sub",
        resp(body=sub_body(u["c.example"])),
        resp(body=sub_body(u["c.example"])),
        resp(body=sub_body(u["b.example"])),
    )
    router.set_api("POST /scan", resp(body={"outcome": "cached"}))
    router.set_api(
        "POST /cache/refresh",
        resp(429, {"detail": "Results were refreshed recently"}, headers={"Retry-After": "300"}),
    )
    router.run_until(back_to_monitor(router, u["b.example"]))
    assert len(router.api_calls("POST /cache/refresh")) == 1  # not retried into the cooldown


INJECTIONS = [
    "vless://11111111-2222-3333-4444-555555555555@b.example:443?x=$(reboot)",
    "vless://11111111-2222-3333-4444-555555555555@b.example:443?x='a'",
    "vless://11111111-2222-3333-4444-555555555555@b.example:443?x=`id`",
    "vless://11111111-2222-3333-4444-555555555555@b.example:443?x=a b",
    "vless://not-a-uuid@b.example:443?type=tcp",
    "vless://11111111-2222-3333-4444-555555555555@b.example:99999?type=tcp",
    "vless://11111111-2222-3333-4444-555555555555@b.example;rm:443?type=tcp",
    "vmess://eyJ2IjoiMiJ9",
    "vless://11111111-2222-3333-4444-555555555555@b.example:443?" + "a" * 3000,
]


@pytest.mark.parametrize(
    "body",
    [
        "",
        "<html>502 Bad Gateway</html>",
        base64.b64encode(b"\x00\xffgarbage").decode(),
        "\n".join(INJECTIONS),
        base64.b64encode("\n".join(INJECTIONS).encode()).decode(),
    ],
)
def test_malformed_or_empty_subscription_is_rejected(router: Router, body: str) -> None:
    router.set_node("a.example", False)
    router.set_node("b.example", True)
    router.set_api("GET /vless/sub", resp(body=body))
    router.set_api("POST /scan", resp(body={"outcome": "cached"}))
    router.run_until(lambda st: st["STATE"] == "SCAN")
    # Only the self-test of the active node; nothing from the rejected subscription.
    assert [c["args"][0] for c in router.calls("sing-box-fetch")] == ["a.example"]
    assert router.load()["uci"]["podkop.main.proxy_string"] == router.urls["a.example"]
    assert "0 usable" in router.logs()


def test_base64_subscription_is_accepted(router: Router) -> None:
    u = router.urls
    router.set_node("a.example", False)
    router.set_node("b.example", True)
    router.set_api("GET /vless/sub", resp(body=sub_body(u["b.example"], b64=True)))
    router.run_until(back_to_monitor(router, u["b.example"]))


def test_candidate_rejected_by_podkop_parser_is_not_applied(router: Router) -> None:
    router.set_node("a.example", False)
    bad = "vless://11111111-2222-3333-4444-555555555555@badparse.example:443?type=tcp"
    router.set_api("GET /vless/sub", resp(body=bad + "\n"))
    router.set_api("POST /scan", resp(body={"outcome": "cached"}))
    router.run_until(lambda st: st["STATE"] == "SCAN")
    assert "failed isolated test (parse)" in router.logs()
    assert router.reloads() == []
