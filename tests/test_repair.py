"""Router self-repair: WAN interface restarts, router DNS, stuck Podkop with a working node."""

from __future__ import annotations

from conftest import Router, resp, sub_body


def reboot(r: Router) -> None:
    """tmpfs state is gone and uptime restarts; /etc survives."""
    if r.state_dir.exists():
        for f in r.state_dir.iterdir():
            if f.is_file():
                f.unlink()
    r.set_time(20)


def wan(r: Router, up: bool, internet: bool | None = None, **extra: object) -> None:
    def fn(w: dict) -> None:
        w["wan_up"] = up
        w["internet"] = up if internet is None else internet
        w.update(extra)

    r.update(fn)


# ------------------------------------------------------------------- WAN ---


def test_wan_that_does_not_come_up_after_boot_is_restarted(router: Router) -> None:
    reboot(router)
    wan(router, False, wan_restart_fixes=True)
    st = router.run_until(lambda st: "class=HEALTHY" in st.get("D_SUMMARY", ""), max_steps=40)
    restarts = router.wan_restarts()
    assert len(restarts) == 1
    # Boot grace (120 s) + fail threshold (3 checks): not earlier, but within ~4 min.
    assert 120 + 60 <= restarts[0]["t"] <= 240
    assert "restarting interface 'wan' (attempt 1)" in router.logs()
    assert "WAN is up again after 1 interface restart(s)" in router.logs()
    assert st["STATE"] == "MONITOR"
    assert router.reloads() == [] and router.api_calls("GET /vless/sub") == []


def test_isp_outage_restarts_wan_with_backoff_and_no_vpn_action(router: Router) -> None:
    wan(router, True, internet=False)  # PPPoE up, nothing behind it; a restart does not help
    router.set_config(check_interval="120")  # fewer ticks; the backoff is what is tested
    start = router.now
    router.run_until(lambda st: router.now - start >= 3 * 3600, max_steps=400)
    times = [c["t"] for c in router.wan_restarts()]
    gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
    assert len(times) >= 4
    assert gaps == sorted(gaps), "backoff must not shrink"
    assert max(gaps) <= 1800 + 60
    assert sum(1 for t in times if t >= start + 2 * 3600) <= 3  # steady state: at most ~2/hour
    assert router.reloads() == [] and router.api_calls() == []
    assert router.calls("sing-box-fetch") == []


def test_icmp_filtered_by_isp_is_not_a_wan_outage(router: Router) -> None:
    router.update(lambda w: w.__setitem__("icmp_blocked", True))
    st = router.run_steps(12)
    assert "class=HEALTHY" in st["D_SUMMARY"]
    assert router.calls("ifctl") == []


def test_wan_carrying_traffic_is_never_restarted(router: Router) -> None:
    # The router's own probes fail, but LAN clients are clearly using the WAN.
    wan(router, True, internet=False)
    rx = 10_000_000
    for _ in range(20):
        rx += 5_000_000
        router.set_rx(rx)
        router.step()
    assert router.calls("ifctl") == []
    assert router.logs().count("WAN is carrying traffic") == 1


def test_idle_wan_counter_does_not_block_restart(router: Router) -> None:
    wan(router, True, internet=False, wan_restart_fixes=True)
    router.set_rx(10_000_000)  # counter present but not moving
    router.run_until(lambda st: router.wan_restarts() != [], max_steps=10)


def test_manually_stopped_wan_is_left_alone(router: Router) -> None:
    wan(router, False, wan_autostart=False)
    router.run_steps(20)
    assert router.calls("ifctl") == []
    assert router.logs().count("stopped manually") == 1


def test_unknown_wan_interface_is_never_touched(router: Router) -> None:
    router.set_config(wan_interface="wan_typo")
    wan(router, False)
    router.run_steps(10)
    assert router.calls("ifctl") == []
    assert router.logs().count("WAN interface 'wan_typo' not found") == 1


def test_wan_repair_can_be_disabled(router: Router) -> None:
    router.set_config(wan_repair="0")
    wan(router, False)
    router.run_steps(20)
    assert router.calls("ifctl") == []


def test_wan_repair_works_while_podkop_is_stopped(router: Router) -> None:
    router.update(lambda w: w["uci"].__setitem__("podkop.settings.shutdown_correctly", "1"))
    wan(router, False, wan_restart_fixes=True)
    router.run_until(lambda st: router.wan_restarts() != [], max_steps=10)
    assert router.reloads() == []


def test_wan_repair_is_not_delayed_by_long_recovery_waits(router: Router) -> None:
    router.set_node("a.example", False)
    router.set_api("GET /vless/sub", resp(body=sub_body(router.urls["b.example"])))
    router.set_api("POST /scan", resp(body={"outcome": "cached"}))
    router.set_api("POST /cache/refresh", resp(body={"outcome": "started"}))
    router.run_until(lambda st: st["STATE"] == "REFRESH_WAIT", max_steps=200)
    wan(router, False, wan_restart_fixes=True)
    t0 = router.now
    router.run_until(lambda st: router.wan_restarts() != [], max_steps=20)
    assert router.now - t0 <= 4 * 60


def test_service_restart_after_wan_restart_does_not_repeat_it(router: Router) -> None:
    wan(router, False)
    router.run_until(lambda st: router.wan_restarts() != [], max_steps=10)
    for _ in range(3):  # procd respawn: tick again without the clock moving
        router.cli("tick")
    assert len(router.wan_restarts()) == 1


# ------------------------------------------------------------ router DNS ---


def test_dead_dnsmasq_is_restarted(router: Router) -> None:
    def dead(w: dict) -> None:
        w["dnsmasq"] = False
        w["dns"]["127.0.0.1"] = False

    router.update(dead)
    st = router.run_until(lambda st: router.calls("dnsmasq-init") != [], max_steps=10)
    assert "class=DNSMASQ_DOWN" in st["D_SUMMARY"]
    assert router.reloads() == []
    st = router.run_steps(3)
    assert "class=HEALTHY" in st["D_SUMMARY"]


def test_dns_chain_escalates_from_podkop_reload_to_dnsmasq_restart(router: Router) -> None:
    def broken(w: dict) -> None:
        w["dns"]["127.0.0.1"] = False
        w["reload_fixes"] = False  # a Podkop reload does not help

    router.update(broken)
    router.run_until(lambda st: router.calls("dnsmasq-init") != [], max_steps=40)
    assert len(router.reloads()) == 1  # tried Podkop first, then dnsmasq
    st = router.run_steps(3)
    assert "class=HEALTHY" in st["D_SUMMARY"]


# -------------------------------------------------------- stuck sing-box ---


def test_stuck_podkop_with_working_node_is_reloaded_not_switched(router: Router) -> None:
    router.set_node("a.example", isolated=True, live=False)
    router.update(lambda w: w.__setitem__("reload_revives", True))
    st = router.run_until(lambda st: len(router.reloads()) == 1, max_steps=20)
    st = router.run_steps(3)
    assert "class=HEALTHY" in st["D_SUMMARY"]
    assert router.proxy() == router.urls["a.example"]  # same node kept
    assert router.api_calls("GET /vless/sub") == []
    assert "works in isolation; reloading Podkop instead of switching" in router.logs()


def test_self_reload_is_tried_once_then_nodes_are_switched(router: Router) -> None:
    router.set_node("a.example", isolated=True, live=False)  # reload does not revive it
    router.set_node("b.example", True)
    router.set_api("GET /vless/sub", resp(body=sub_body(router.urls["b.example"])))
    router.run_until(lambda st: st["STATE"] == "MONITOR" and "b.example" in router.proxy(), max_steps=120)
    assert router.logs().count("works in isolation") == 1
