"""Hardening: faults that must neither harm the router nor silently disable protection."""

from __future__ import annotations

import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

from conftest import SCRIPT, SHELL, Router, resp, sub_body
from test_router import setw, telegram_on, wifi, wifictl
from test_safety import start_failover


def dnsmasq_restarts(r: Router) -> list[dict]:
    return [c for c in r.calls("dnsmasq-init") if c["args"][0] == "restart"]


def run_for(r: Router, seconds: int, max_steps: int = 400) -> None:
    end = r.now + seconds
    for _ in range(max_steps):
        if r.now >= end:
            return
        r.step()
    raise AssertionError("clock did not advance")


# ------------------------------------------------- user-disabled dnsmasq ---


def test_disabled_dnsmasq_with_other_resolver_is_never_started(router: Router) -> None:
    setw(router, dnsmasq=False, dnsmasq_enabled=False, other_resolver=True)
    st = router.run_steps(30)
    assert dnsmasq_restarts(router) == []
    assert "class=HEALTHY" in st["D_SUMMARY"]


def test_disabled_dnsmasq_is_never_started_even_if_dns_fails(router: Router) -> None:
    setw(router, dnsmasq=False, dnsmasq_enabled=False)
    router.run_steps(40)
    assert dnsmasq_restarts(router) == []


def test_missing_dnsmasq_process_with_answering_dns_is_left_alone(router: Router) -> None:
    setw(router, dnsmasq=False, other_resolver=True)  # enabled, but something else answers on :53
    router.run_steps(30)
    assert dnsmasq_restarts(router) == []


def test_dnsmasq_is_repaired_during_a_long_node_search(router: Router) -> None:
    router.set_node("a.example", False)
    router.set_api("GET /vless/sub", resp(body=sub_body(router.urls["b.example"])))
    router.set_api("POST /scan", resp(body={"outcome": "cached"}))
    router.set_api("POST /cache/refresh", resp(body={"outcome": "started"}))
    router.run_until(lambda st: st["STATE"] == "REFRESH_WAIT", max_steps=200)
    setw(router, dnsmasq=False)
    router.run_until(lambda st: dnsmasq_restarts(router) != [], max_steps=40)
    assert router.state()["STATE"] != "MONITOR"  # recovery went on
    assert len(dnsmasq_restarts(router)) == 1


# --------------------------------------------------------------- rollback ---


def test_failing_rollback_backs_off_and_notifies_once(router: Router) -> None:
    telegram_on(router, direct=True)
    start_failover(router, "b.example")
    setw(router, reload_rcs=[1] * 200)
    run_for(router, 4800)
    assert len(router.reloads()) <= 10
    alerts = [t for t in router.telegrams() if "Не удаётся вернуть" in t["text"]]
    assert len(alerts) == 1


def test_user_stopping_podkop_during_verification_cancels_without_reload(router: Router) -> None:
    start_failover(router, "b.example")
    router.run_until(lambda st: st["STATE"] == "VERIFY", max_steps=100)
    router.update(lambda w: w["uci"].__setitem__("podkop.settings.shutdown_correctly", "1"))
    before = len(router.reloads())
    router.run_steps(6)
    assert router.state()["STATE"] == "MONITOR"
    assert len(router.reloads()) == before


# ---------------------------------------------------------- Clash / probes ---


def test_unreachable_clash_and_dead_path_probe_never_switch_a_node(router: Router) -> None:
    setw(router, clash_reachable=False, path_broken=True)
    st = router.run_steps(50)
    assert "class=TUNNEL_UNKNOWN" in st["D_SUMMARY"]
    assert router.reloads() == [] and router.calls("sing-box-fetch") == []
    assert not [c for c in router.calls("uci") if c["args"][0] == "set"]


def test_clash_secret_is_sent_with_every_probe_url(router: Router) -> None:
    def fn(w: dict) -> None:
        w["uci"]["podkop.settings.enable_yacd"] = "1"
        w["uci"]["podkop.settings.yacd_secret_key"] = "s3cret"
        w["clash_secret"] = "s3cret"
        w["clash_fail_urls"] = ["gstatic"]  # first URL fails, the second must still be tried

    router.update(fn)
    st = router.run_steps(3)
    assert "node=ok" in st["D_SUMMARY"] and "class=HEALTHY" in st["D_SUMMARY"]


# ------------------------------------------------------------ hung services ---


def test_hung_podkop_reload_does_not_stop_wan_repair(router: Router) -> None:
    router.set_config(service_timeout="10")
    setw(router, singbox=False, reload_fixes=False, reload_hang=True)
    try:
        router.run_until(lambda st: "not finishing" in router.logs(), max_steps=30)
        setw(router, wan_up=False, internet=False, wan_restart_fixes=True)
        router.run_until(lambda st: router.wan_restarts() != [], max_steps=40)
        assert len(router.reloads()) == 1  # no second reload while the first one hangs
    finally:
        (router.base / "hang_release").write_text("")


# ---------------------------------------------------------- notifications ---


def test_undeliverable_telegram_is_retried_with_backoff(router: Router) -> None:
    telegram_on(router)
    # The tunnel works, but the node cannot reach Telegram in isolation.
    router.set_node("a.example", isolated=False, live=True)
    setw(router, dnsmasq=False)  # produces a notification
    run_for(router, 3600, max_steps=300)
    via_node = [t for t in router.telegrams() if t["via"] != "direct"]
    direct = [t for t in router.telegrams() if t["via"] == "direct"]
    assert 1 <= len(direct) <= 8
    assert len(via_node) <= 7


# ------------------------------------------------------------------- WAN ---


def test_nonstandard_wan_name_is_detected(router: Router) -> None:
    setw(router, wan_name="wwan")
    st = router.run_steps(10)
    assert "class=HEALTHY" in st["D_SUMMARY"] and router.calls("ifctl") == []
    assert st["WAN_IF"] == "wwan"


def test_nonstandard_wan_is_restarted_by_its_own_name(router: Router) -> None:
    setw(router, wan_name="wwan", wan_up=False, internet=False, wan_restart_fixes=True)
    router.run_until(lambda st: router.wan_restarts() != [], max_steps=30)
    assert "restarting interface 'wwan'" in router.logs()


def test_missing_wan_interface_judges_by_probes_and_does_not_disable_monitoring(router: Router) -> None:
    setw(router, no_wan_interface=True)
    st = router.run_steps(10)
    assert "class=HEALTHY" in st["D_SUMMARY"]
    setw(router, internet=False, wan_up=False)
    st = router.run_steps(10)
    assert "class=WAN_DOWN" in st["D_SUMMARY"] and router.calls("ifctl") == []


# ----------------------------------------------------------------- config ---


def test_boolean_options_follow_procd_spelling(router: Router) -> None:
    router.set_config(check_full_path="off", wan_repair="no", wifi_repair="false")
    setw(router, wan_up=False, internet=False, wan_restart_fixes=True)
    router.run_steps(20)
    assert router.calls("ifctl") == [] and router.calls("fullpath") == []


def test_malformed_probe_targets_fall_back_to_defaults(router: Router) -> None:
    router.set_config(internet_target="-f 1.1.1.1", clash_api="evil;host", wan_interface="a b")
    st = router.run_steps(3)
    assert "class=HEALTHY" in st["D_SUMMARY"]
    for needle in ("internet_target", "clash_api", "wan_interface"):
        assert needle in router.logs()


# ------------------------------------------------------------------ Wi-Fi ---


def test_mesh_radio_without_hostapd_is_not_restarted(router: Router) -> None:
    wifi(router, radio0={"daemon": False, "mode": "mesh"})
    router.run_steps(40)
    assert wifictl(router) == []


def test_ap_radio_without_hostapd_is_restarted(router: Router) -> None:
    wifi(router, radio0={"daemon": False})
    router.run_until(lambda st: wifictl(router) != [], max_steps=60)


# -------------------------------------------------------------- lifecycle ---


def test_run_waits_for_a_stale_lock_instead_of_failing(router: Router) -> None:
    env = router.env()
    env["WD_LOCK_WAIT"] = "20"
    with router.lock.open("w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        proc = subprocess.Popen(
            [SHELL, str(SCRIPT), "run"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            time.sleep(3)
            assert proc.poll() is None  # still waiting, not crashed
            assert "started" not in router.logs()
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)
    try:
        end = time.time() + 20
        while "started" not in router.logs() and time.time() < end:
            time.sleep(0.2)
        assert "started" in router.logs()
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()


def test_cli_commands_use_a_private_scratch_directory(router: Router) -> None:
    router.cli("diagnose")
    assert not [p for p in router.state_dir.iterdir() if p.name.startswith("cli.")]


# ------------------------------------------------- selfcheck / compatibility ---


def test_selfcheck_reports_a_healthy_setup(router: Router) -> None:
    out = router.cli("selfcheck").stdout
    assert "FAIL" not in out and "ИТОГ" in out
    assert "WAN-интерфейс: wan" in out and "dnsmasq работает" in out
    assert router.cli("version").stdout.startswith("podkop-watchdog ")


def test_selfcheck_flags_an_old_singbox(router: Router) -> None:
    setw(router, singbox_version="1.11.4")
    out = router.cli("selfcheck").stdout
    assert "singbox_1.11_lt_1.12" in out


def test_selfcheck_tolerates_a_user_disabled_dnsmasq(router: Router) -> None:
    setw(router, dnsmasq=False, dnsmasq_enabled=False, other_resolver=True)
    out = router.cli("selfcheck").stdout
    assert "выключен пользователем" in out and "FAIL" not in out


def test_incompatible_podkop_parser_disables_failover_but_not_router_repair(router: Router) -> None:
    telegram_on(router, direct=True)
    (router.podkop_lib / "sing_box_config_facade.sh").write_text(
        "sing_box_cf_add_proxy_outbound() { exit 1; }\n"
    )
    start_failover(router, "b.example")
    router.run_steps(12)
    assert router.reloads() == [] and router.calls("sing-box-fetch") == []
    assert "failover is disabled" in router.logs() or "failover disabled" in router.logs()
    assert any("автопереключение узлов отключено" in t["text"] for t in router.telegrams())
    # Router-level repair still works.
    setw(router, dnsmasq=False)
    router.run_until(lambda st: dnsmasq_restarts(router) != [], max_steps=20)


def test_clash_address_secret_and_tag_come_from_the_singbox_config(router: Router) -> None:
    (router.base / "singbox.json").write_text(
        json.dumps(
            {
                "experimental": {"clash_api": {"external_controller": "0.0.0.0:9090", "secret": "abc"}},
                "outbounds": [{"tag": "main-out-2"}],
            }
        )
    )
    setw(router, clash_secret="abc", clash_tag="main-out-2")
    st = router.run_steps(3)
    assert "node=ok" in st["D_SUMMARY"] and "class=HEALTHY" in st["D_SUMMARY"]


# --------------------------------------------------- spam / flash wear limits ---


def test_unfixable_podkop_failure_escalates_once_instead_of_spamming(router: Router) -> None:
    telegram_on(router, direct=True)
    router.set_config(check_interval="300")
    setw(router, singbox=False, reload_fixes=False)
    run_for(router, 2 * 3600)
    texts = [t["text"] for t in router.telegrams()]
    assert len([t for t in texts if "Перезапустил Podkop" in t]) <= 2
    assert len([t for t in texts if "не устраняется перезапусками" in t]) == 1


def test_flapping_check_does_not_wear_the_flash(router: Router) -> None:
    for i in range(40):
        setw(router, path_broken=(i % 2 == 0))
        router.step()
    assert len(router.events().splitlines()) <= 14


# ----------------------------------------------- findings of the second audit ---


def test_jq_filters_avoid_regex_functions_missing_from_openwrt_jq() -> None:
    """OpenWrt's default jq has no oniguruma: test()/match()/capture() fail at run time."""
    from conftest import LIB

    bad = re.compile(r"[|(]\s*(test|match|capture|gsub|scan|splits)\(")
    for sh in LIB.glob("*.sh"):
        assert not bad.search(sh.read_text()), f"{sh.name} uses a jq regex function"


def test_queued_messages_all_go_out_at_once_through_a_working_node_route(router: Router) -> None:
    telegram_on(router)  # blocked directly, the node route works
    q = router.state_dir / "notify.queue"
    router.state_dir.mkdir(parents=True, exist_ok=True)
    q.write_text("".join(f"01.01 00:00 msg {i}\n" for i in range(5)))
    router.run_steps(3)
    assert not q.read_text().strip()
    assert len([t for t in router.telegrams() if t["via"] == "a.example"]) == 5


def test_wan_that_comes_up_later_on_another_interface_is_followed(router: Router) -> None:
    setw(router, wan_up=False, internet=False, secondary={"name": "wwan", "up": False})
    st = router.run_steps(3)
    assert "class=WAN_DOWN" in st["D_SUMMARY"] and st["WAN_IF"] == ""  # a guess is never remembered
    setw(router, internet=True, secondary={"name": "wwan", "up": True})
    st = router.run_steps(3)
    assert "class=HEALTHY" in st["D_SUMMARY"] and st["WAN_IF"] == "wwan"


def test_working_internet_over_another_link_is_not_a_wan_outage(router: Router) -> None:
    # "wan" is configured by default-detection but unplugged; a backup link carries traffic.
    setw(router, wan_up=False, internet=True, secondary={"name": "wwan", "up": True})
    st = router.run_steps(6)
    assert "class=HEALTHY" in st["D_SUMMARY"] and router.calls("ifctl") == []


def test_access_point_mode_has_no_wan_to_repair(router: Router) -> None:
    setw(router, wan_up=False, internet=False, lan_default=True)
    st = router.run_steps(8)
    assert "class=WAN_DOWN" in st["D_SUMMARY"] and router.calls("ifctl") == []


def test_finished_service_action_is_not_mistaken_for_a_running_one(router: Router) -> None:
    router.state_dir.mkdir(parents=True, exist_ok=True)
    (router.state_dir / "child.podkop").write_text(f"{os.getpid()} 900\n")  # pid now alive, reused
    (router.state_dir / "child.podkop.900.rc").write_text("0\n")  # ...but the action itself finished
    setw(router, singbox=False)
    router.run_until(lambda st: router.reloads() != [], max_steps=20)


def test_running_service_action_is_not_restarted_and_costs_no_budget(router: Router) -> None:
    router.state_dir.mkdir(parents=True, exist_ok=True)
    (router.state_dir / "child.podkop").write_text(f"{os.getpid()} 990\n")  # genuinely still running
    setw(router, singbox=False)
    st = router.run_steps(10)
    assert router.reloads() == [] and st["RESTARTS"] == "" and st["ESC_N"] == "0"


def test_clash_blips_do_not_spam_but_a_real_outage_alerts_once(router: Router) -> None:
    telegram_on(router, direct=True)
    for i in range(10):
        setw(router, clash_reachable=(i % 2 == 0))
        router.step()
    assert not [t for t in router.telegrams() if "Clash API" in t["text"]]
    setw(router, clash_reachable=False)
    router.run_steps(8)
    assert len([t for t in router.telegrams() if "Clash API" in t["text"]]) == 1


def test_a_rollback_that_never_succeeds_eventually_returns_to_monitoring(router: Router) -> None:
    telegram_on(router, direct=True)
    router.set_config(check_interval="600")  # coarse steps: the back-off spans hours
    start_failover(router, "b.example")
    setw(router, reload_rcs=[1] * 400)
    router.run_until(lambda st: any("за 8 попыток" in t["text"] for t in router.telegrams()), max_steps=80)
    assert router.state()["STATE"] != "ROLLBACK"


def test_installer_keeps_the_users_config_and_is_idempotent(router: Router, tmp_path: Path) -> None:
    from conftest import ROOT

    ipk = subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_ipk.py"), str(tmp_path / "dist")],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    target = tmp_path / "root"
    (target / "etc/config").mkdir(parents=True)
    (target / "etc/config/podkop-watchdog").write_text(
        "config watchdog 'main'\n\toption telegram_token 'KEEP'\n"
    )
    env = {**os.environ, "INSTALL_ROOT": str(target)}
    target.chmod(0o755)
    for _ in range(2):  # a strict umask must not leak into the target root's mode
        subprocess.run(
            ["sh", "-c", 'umask 077; exec "$0" "$1" "$2"', SHELL, str(ROOT / "scripts/install.sh"), ipk],
            env=env,
            check=True,
            capture_output=True,
        )
    assert target.stat().st_mode & 0o777 == 0o755
    assert "KEEP" in (target / "etc/config/podkop-watchdog").read_text()
    assert (target / "usr/bin/podkop-watchdog").stat().st_mode & 0o111
    assert (target / "etc/config/podkop-watchdog").stat().st_mode & 0o777 == 0o600
    assert (target / "usr/lib/podkop-watchdog/machine.sh").exists()
