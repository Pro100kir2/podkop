"""Safety and lifecycle: rollback, LKG, outages, persistence, locking, reboot, procd."""

from __future__ import annotations

import fcntl
import signal
import subprocess
import time

from conftest import FILES, SCRIPT, SHELL, Router, resp, sub_body


def bare(url: str) -> str:
    return url.split("#", 1)[0]


def back_to_monitor(r: Router, url: str):
    return lambda st: st["STATE"] == "MONITOR" and r.proxy() == bare(url)


def uci_proxy_sets(r: Router) -> list[str]:
    hosts = []
    for c in r.calls("uci"):
        if c["args"][0] == "set" and "proxy_string=" in c["args"][1]:
            hosts.append(c["args"][1].split("@", 1)[1].split(":", 1)[0])
    return hosts


def start_failover(r: Router, *hosts_ok: str, sub: list[str] | None = None) -> None:
    r.set_node("a.example", False)
    for h in hosts_ok:
        r.set_node(h, True)
    urls = [r.urls[h] for h in (sub or ["b.example", "c.example"])]
    r.set_api("GET /vless/sub", resp(body=sub_body(*urls)))
    r.set_api("POST /scan", resp(body={"outcome": "cached"}))
    r.set_api("POST /cache/refresh", resp(body={"outcome": "started"}))


# ------------------------------------------------------- apply / rollback ---


def test_failed_uci_commit_leaves_config_untouched(router: Router) -> None:
    start_failover(router, "b.example", "c.example")
    router.update(lambda w: w.__setitem__("uci_commit_fail", True))
    router.run_until(lambda st: st["STATE"] == "SCAN")
    assert router.reloads() == []
    assert router.proxy() == router.urls["a.example"]
    assert router.load()["staged"] == {}  # failed change reverted, nothing left staged
    assert "uci update failed" in router.logs()


def test_failed_podkop_reload_rolls_back_then_next_candidate(router: Router) -> None:
    start_failover(router, "b.example", "c.example")
    router.update(lambda w: w.__setitem__("reload_rcs", [1]))  # first reload fails
    router.run_until(back_to_monitor(router, router.urls["c.example"]))
    assert uci_proxy_sets(router) == ["b.example", "a.example", "c.example"]
    assert "rolling back" in router.logs()


def test_failed_post_switch_verification_rolls_back(router: Router) -> None:
    start_failover(router, "c.example")
    router.set_node("b.example", isolated=True, live=False)  # works alone, not via Podkop
    router.run_until(back_to_monitor(router, router.urls["c.example"]))
    assert uci_proxy_sets(router) == ["b.example", "a.example", "c.example"]
    assert len(router.reloads()) == 3
    assert "failed verification" in router.logs()
    assert "rolled back to the previous configuration" in router.logs()
    assert router.lkg() == bare(router.urls["c.example"])


def test_node_failing_after_switch_is_not_retried_in_same_cycle(router: Router) -> None:
    start_failover(router, sub=["b.example"])
    router.set_node("b.example", isolated=True, live=False)
    # Initial fetch + post-scan fetch both list b; it is applied only once per cycle.
    router.run_until(lambda st: st["STATE"] == "REFRESH", max_steps=150)
    assert uci_proxy_sets(router) == ["b.example", "a.example"]
    assert router.proxy() == router.urls["a.example"]  # previous config restored
    # A new refresh cycle gives it one more chance.
    router.run_until(lambda st: st["STATE"] == "REFRESH_WAIT", max_steps=150)
    assert uci_proxy_sets(router).count("b.example") == 2


def test_switch_limit_per_cycle(router: Router) -> None:
    hosts = ["b.example", "c.example", "d.example"]
    start_failover(router, sub=hosts)
    for h in hosts:
        router.set_node(h, isolated=True, live=False)
    router.set_config(max_applies_per_round="2", restart_min_interval="10")
    router.run_until(lambda st: st["STATE"] == "SCAN", max_steps=150)
    assert uci_proxy_sets(router) == ["b.example", "a.example", "c.example", "a.example"]


def test_last_known_good_is_tried_first_without_api(router: Router) -> None:
    router.persist_dir.mkdir(parents=True)
    (router.persist_dir / "lkg").write_text(router.urls["c.example"] + "\n")
    router.set_node("a.example", False)
    router.set_node("c.example", True)
    # LKG is stored verbatim (with its display name), so compare the full string.
    router.run_until(lambda st: st["STATE"] == "MONITOR" and router.proxy() == router.urls["c.example"])
    assert [c for c in router.api_calls() if c["args"][0] != "GET /health"] == []


def test_lkg_is_retested_after_each_subscription(router: Router) -> None:
    router.persist_dir.mkdir(parents=True)
    (router.persist_dir / "lkg").write_text(router.urls["c.example"] + "\n")
    router.set_node("a.example", False)
    router.set_node("c.example", False)
    router.set_api("GET /vless/sub", resp(body=sub_body(router.urls["d.example"])))
    router.set_api("POST /scan", resp(body={"outcome": "cached"}))
    router.run_until(lambda st: st["STATE"] == "REFRESH")
    tested = [c["args"][0] for c in router.calls("sing-box-fetch")]
    assert tested.count("c.example") >= 2  # lkg phase + appended to subscription lists


# --------------------------------------------------------------- outages ---


def test_wan_outage_causes_no_vpn_action(router: Router) -> None:
    router.update(lambda w: w.__setitem__("wan_up", False))
    router.set_node("a.example", False)
    st = router.run_steps(15)
    assert st["STATE"] == "MONITOR" and "class=WAN_DOWN" in st["D_SUMMARY"]
    assert router.reloads() == [] and router.api_calls() == []
    assert router.logs().count("class=WAN_DOWN") == 1  # logged once, not every tick


def test_isp_outage_with_link_up_causes_no_vpn_action(router: Router) -> None:
    router.update(lambda w: w.__setitem__("internet", False))
    router.set_node("a.example", False)
    router.run_steps(15)
    assert router.reloads() == [] and router.api_calls() == []
    assert router.calls("sing-box-fetch") == []


def test_upstream_dns_outage_causes_no_vpn_action(router: Router) -> None:
    router.update(lambda w: w.__setitem__("dns", {"127.0.0.1": False, "8.8.8.8": False, "77.88.8.8": False}))
    router.set_node("a.example", False)
    st = router.run_steps(15)
    assert "class=DNS_UPSTREAM_DOWN" in st["D_SUMMARY"]
    assert router.reloads() == [] and router.calls("sing-box-fetch") == []


def test_local_dns_chain_failure_reloads_podkop_with_budget(router: Router) -> None:
    def broken_dns_chain(w: dict) -> None:
        w["dns"]["127.0.0.1"] = False
        w["reload_fixes"] = False  # a reload does not fix it

    router.update(broken_dns_chain)
    router.set_config(restart_max_per_hour="2", restart_min_interval="60")
    start = router.now
    router.run_until(lambda st: router.now - start >= 3000, max_steps=500)
    assert len(router.reloads()) == 2  # budget respected
    assert "restart budget exhausted" in router.logs()
    assert router.calls("sing-box-fetch") == []  # not a node problem


def test_podkop_down_reloaded_after_threshold(router: Router) -> None:
    router.update(lambda w: w.__setitem__("singbox", False))
    router.run_steps(2)
    assert router.reloads() == []
    router.run_steps(1)
    assert len(router.reloads()) == 1
    st = router.run_steps(3)
    assert "class=HEALTHY" in st["D_SUMMARY"]


def test_full_path_probe_uses_check_endpoint(router: Router) -> None:
    st = router.run_steps(2)
    assert "path=1" in st["D_SUMMARY"]
    assert {c["args"][0] for c in router.calls("fullpath")} == {"/check"}


def test_full_path_failure_is_reported_but_never_acted_on(router: Router) -> None:
    # ip.podkop.fyi is a third-party service: its outage must not cause reloads.
    router.update(lambda w: w.__setitem__("path_broken", True))
    st = router.run_steps(10)
    assert "class=PATH_DOWN" in st["D_SUMMARY"]
    assert router.reloads() == [] and router.calls("sing-box-fetch") == []
    assert router.logs().count("class=PATH_DOWN") == 1


def test_switch_verified_by_tunnel_even_if_path_probe_down(router: Router) -> None:
    start_failover(router, "b.example")
    router.update(lambda w: w.__setitem__("path_broken", True))
    router.run_until(back_to_monitor(router, router.urls["b.example"]))
    assert len(router.reloads()) == 1  # no rollback


def test_wan_loss_during_recovery_pauses_api_calls(router: Router) -> None:
    start_failover(router, "b.example")
    router.set_api("GET /vless/sub", resp(503), resp(body=sub_body(router.urls["b.example"])))
    router.run_until(lambda st: st["STATE"] == "FETCH" and st["ATTEMPT"] == "1")
    router.update(lambda w: w.__setitem__("wan_up", False))
    before = len(router.api_calls())
    st = router.run_steps(10)
    # At most the already scheduled retry goes out; its failure does not burn an attempt.
    assert st["STATE"] == "FETCH" and st["ATTEMPT"] == "1"
    assert len(router.api_calls()) <= before + 1
    assert "recovery paused" in router.logs()
    router.update(lambda w: w.__setitem__("wan_up", True))
    router.run_until(back_to_monitor(router, router.urls["b.example"]))


def test_active_node_recovering_by_itself_cancels_recovery(router: Router) -> None:
    start_failover(router)
    router.set_api("GET /vless/sub", resp(503))
    router.run_until(lambda st: st["STATE"] == "FETCH")
    router.set_node("a.example", True)
    router.run_until(lambda st: st["STATE"] == "MONITOR", max_steps=30)
    assert router.reloads() == []
    assert "recovery cancelled" in router.logs()


def test_podkop_stopped_by_user_is_left_alone(router: Router) -> None:
    router.update(lambda w: w["uci"].__setitem__("podkop.settings.shutdown_correctly", "1"))
    router.update(lambda w: w.__setitem__("singbox", False))
    router.run_steps(10)
    assert router.reloads() == [] and router.calls("sing-box-fetch") == []


def test_unmanaged_podkop_mode_is_never_rewritten(router: Router) -> None:
    router.update(lambda w: w["uci"].__setitem__("podkop.main.proxy_config_type", "urltest"))
    router.set_node("a.example", False)
    router.run_steps(10)
    assert router.reloads() == [] and uci_proxy_sets(router) == []
    assert router.logs().count("not switching") == 1


def test_pending_luci_changes_postpone_switch(router: Router) -> None:
    start_failover(router, "b.example")
    router.update(lambda w: w["staged"].__setitem__("podkop.settings.log_level", "debug"))
    router.run_until(lambda st: st["STATE"] == "APPLY")
    router.run_steps(5)
    assert uci_proxy_sets(router) == [] and router.state()["STATE"] == "APPLY"
    router.update(lambda w: w["staged"].clear())
    router.run_until(back_to_monitor(router, router.urls["b.example"]))


def test_low_memory_postpones_candidate_tests(router: Router) -> None:
    start_failover(router, "b.example")
    router.set_mem(4000)
    router.run_until(lambda st: st["STATE"] == "TEST")
    router.run_steps(5)
    assert router.calls("sing-box-fetch") == []
    router.set_mem(50000)
    router.run_until(back_to_monitor(router, router.urls["b.example"]))


def test_api_traffic_is_pinned_to_directly_resolved_address(router: Router) -> None:
    router.run_steps(1)
    call = router.api_calls("GET /health")[0]
    assert call["resolve"] == ["api.scat-search.ru:443:158.160.189.146"]


# ------------------------------------------------ persistence / processes ---


def test_crash_during_apply_resumes_with_verification(router: Router) -> None:
    start_failover(router, "c.example")
    router.run_until(lambda st: st["STATE"] == "APPLY")
    # Simulate a crash after the state was persisted but before uci changed.
    state = (router.state_dir / "state").read_text().replace("STATE=APPLY\n", "STATE=APPLYING\n")
    (router.state_dir / "state").write_text(state)
    router.run_until(lambda st: st["STATE"] == "MONITOR" and router.proxy() != router.urls["a.example"])
    assert "interrupted switch" in router.logs()


def test_restart_does_not_bypass_backoff(router: Router) -> None:
    start_failover(router)
    router.set_api("GET /vless/sub", resp(503))
    router.run_until(lambda st: st["STATE"] == "FETCH" and st["ATTEMPT"] == "1")
    router.set_time(router.now - 5)  # run_until jumped to the retry time; go back before it
    before = len(router.api_calls())
    for _ in range(5):  # e.g. procd respawning the service repeatedly
        router.cli("tick")
    assert len(router.api_calls()) == before


def test_tick_refuses_while_another_instance_holds_lock(router: Router) -> None:
    with router.lock.open("w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        proc = router.cli("tick", check=False)
        assert proc.returncode == 1 and "already running" in proc.stderr
    assert router.calls("clash") == []
    router.cli("tick")  # lock released


def _wait_for(pred, timeout: float = 15) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return
        time.sleep(0.1)
    raise AssertionError("timeout")


def test_run_loop_single_instance_and_clean_stop(router: Router) -> None:
    first = subprocess.Popen(
        [SHELL, str(SCRIPT), "run"],
        env=router.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for(lambda: "status:" in router.logs())
        second = router.cli("run", check=False, timeout=10)
        assert second.returncode == 1 and "already running" in second.stderr
        first.send_signal(signal.SIGTERM)
        assert first.wait(timeout=10) == 0
    finally:
        if first.poll() is None:
            first.kill()
    assert "stopping" in router.logs()
    router.cli("tick")  # lock not held by orphans


def test_disabled_service_exits(router: Router) -> None:
    router.set_config(enabled="0")
    assert router.cli("run", timeout=10).returncode == 0
    assert router.calls("clash") == []


def test_reboot_starts_fresh_with_boot_grace_and_keeps_lkg(router: Router) -> None:
    start_failover(router, "b.example")
    router.run_until(back_to_monitor(router, router.urls["b.example"]))
    # Reboot: tmpfs state is gone, uptime restarts, /etc survives.
    for f in router.state_dir.iterdir():
        if f.is_file():
            f.unlink()
    router.set_time(20)
    router.update(lambda w: w.__setitem__("active", w["uci"]["podkop.main.proxy_string"]))
    calls_before = len(router.calls())
    st = router.step()
    assert st["NEXT_AT"] == "120" and len(router.calls()) == calls_before  # no checks yet
    assert router.lkg() == bare(router.urls["b.example"])
    st = router.step()
    assert st["STATE"] == "MONITOR" and "class=HEALTHY" in st["D_SUMMARY"]


def test_procd_init_script() -> None:
    init = (FILES / "etc/init.d/podkop-watchdog").read_text()
    assert "USE_PROCD=1" in init
    assert 'procd_set_param command "$PROG" run' in init
    assert "procd_set_param respawn 3600 30 5" in init
    assert "procd_add_reload_trigger podkop-watchdog" in init
    # S99podkop-watchdog sorts after S99podkop: starts after Podkop at boot.
    assert "START=99" in init and sorted(["S99podkop-watchdog", "S99podkop"])[0] == "S99podkop"
    assert subprocess.run([SHELL, "-n", str(FILES / "etc/init.d/podkop-watchdog")]).returncode == 0
    keep = (FILES / "lib/upgrade/keep.d/podkop-watchdog").read_text()
    assert keep.strip() == "/etc/podkop-watchdog/"


def test_status_and_diagnose_commands_do_not_leak(router: Router) -> None:
    router.run_steps(3)
    out = router.cli("status").stdout + router.cli("diagnose").stdout
    assert "LKG=present" in out and "class=HEALTHY" in out and "api=1" in out
    assert "vless://" not in out and "a.example" not in out
