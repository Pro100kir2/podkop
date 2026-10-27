"""Router-wide self-repair beyond the VPN: Wi-Fi, dnsmasq, WAN guard, notifications, event log."""

from __future__ import annotations

import re

from conftest import TG_TOKEN, Router


def setw(r: Router, **values: object) -> None:
    """Set top-level world keys."""
    r.update(lambda w: w.update(values))


def wifi(r: Router, **radios: dict) -> None:
    def fn(w: dict) -> None:
        w["wifi"] = {}
        for name, cfg in radios.items():
            w["wifi"][name] = {"up": True, "ifaces": [f"phy{name[-1]}-ap0"], "clients": 0, **cfg}

    r.update(fn)


def wifictl(r: Router, radio: str | None = None) -> list[dict]:
    return [c for c in r.calls("wifictl") if c["args"][0] == "up" and radio in (None, c["args"][1])]


def telegram_on(r: Router, direct: bool = False) -> None:
    r.set_config(telegram_token=TG_TOKEN, telegram_chat_id="-100123")
    setw(r, tg_direct=direct)


# ------------------------------------------------------------------ Wi-Fi ---


def test_radio_that_did_not_come_up_is_restarted_alone(router: Router) -> None:
    wifi(router, radio0={"up": False}, radio1={})
    router.run_until(lambda st: wifictl(router) != [], max_steps=20)
    assert [c["args"][1] for c in wifictl(router)] == ["radio0"]
    router.run_steps(6)
    assert len(wifictl(router)) == 1
    assert "Wi-Fi radio0 works again after 1 restart(s)" in router.logs()


def test_radio_without_hostapd_is_restarted(router: Router) -> None:
    wifi(router, radio0={"daemon": False})
    router.run_until(lambda st: wifictl(router, "radio0") != [], max_steps=20)
    assert "unhealthy (nodaemon)" in router.logs()


def test_stalled_radio_with_clients_is_restarted(router: Router) -> None:
    wifi(router, radio0={"clients": 2})
    router.set_tx("phy0-ap0", 5000)  # never moves
    router.run_until(lambda st: wifictl(router) != [], max_steps=60)
    assert "unhealthy (stalled)" in router.logs()


def test_busy_or_empty_radio_is_not_restarted(router: Router) -> None:
    wifi(router, radio0={"clients": 2}, radio1={"clients": 0})
    tx = 1000
    for _ in range(40):
        tx += 50
        router.set_tx("phy0-ap0", tx)  # radio0 transmits; radio1 is idle but has no clients
        router.step()
    assert router.calls("wifictl") == []


def test_disabled_or_manually_stopped_radio_is_left_alone(router: Router) -> None:
    wifi(router, radio0={"up": False, "disabled": True}, radio1={"up": False, "autostart": False})
    router.run_steps(30)
    assert router.calls("wifictl") == []
    assert router.logs().count("Wi-Fi radio1 was stopped manually") == 1


def test_radio_restarts_back_off(router: Router) -> None:
    wifi(router, radio0={"up": False})
    setw(router, wifi_restart_fixes=False)

    def keep_down(w: dict) -> None:
        w["wifi"]["radio0"]["daemon"] = False

    start = router.now
    while router.now - start < 2 * 3600:
        router.update(keep_down)
        router.step()
    times = [c["t"] for c in wifictl(router)]
    gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
    assert len(times) >= 3
    assert gaps == sorted(gaps) and gaps[0] >= 300 and max(gaps) <= 3600 + 120


# --------------------------------------------------------- router DNS -----


def test_dead_dnsmasq_is_restarted_even_with_podkop_off(router: Router) -> None:
    def fn(w: dict) -> None:
        w["uci"]["podkop.settings.shutdown_correctly"] = "1"
        w["dnsmasq"] = False

    router.update(fn)
    st = router.run_until(lambda st: router.calls("dnsmasq-init") != [], max_steps=10)
    assert "class=DNSMASQ_DOWN" in st["D_SUMMARY"]
    assert router.reloads() == []


def test_dead_dnsmasq_is_restarted_even_without_internet(router: Router) -> None:
    setw(router, dnsmasq=False, internet=False)
    router.run_until(lambda st: router.calls("dnsmasq-init") != [], max_steps=10)


def test_silent_dnsmasq_with_podkop_off_is_restarted(router: Router) -> None:
    def fn(w: dict) -> None:
        w["uci"]["podkop.settings.shutdown_correctly"] = "1"
        w["dns"]["127.0.0.1"] = False  # running but not answering

    router.update(fn)
    st = router.run_until(lambda st: router.calls("dnsmasq-init") != [], max_steps=10)
    assert "class=DNSMASQ_BROKEN" in st["D_SUMMARY"]


def test_podkop_off_and_healthy_router_needs_nothing(router: Router) -> None:
    router.update(lambda w: w["uci"].__setitem__("podkop.settings.shutdown_correctly", "1"))
    st = router.run_steps(8)
    assert "class=PODKOP_OFF" in st["D_SUMMARY"]
    assert router.calls("dnsmasq-init") == [] and router.reloads() == []


# ------------------------------------------------------------- WAN guard ---


def test_wan_restart_held_back_when_lan_keeps_working_after_restart(router: Router) -> None:
    # The router's own probes fail; a restart does not change that; LAN traffic flows.
    setw(router, internet=False)
    router.set_rx(1_000_000)
    router.run_until(lambda st: len(router.wan_restarts()) == 1, max_steps=10)
    rx = 1_000_000
    for i in range(40):  # 20 min of bursty LAN use: traffic every other check
        if i % 2 == 0:
            rx += 2_000_000
            router.set_rx(rx)
        router.step()
    assert len(router.wan_restarts()) == 1
    assert router.state()["WAN_SUSPECT"] == "1"
    assert "WAN restarts held back" in router.logs()
    for _ in range(35):  # traffic stops completely: a restart is allowed again
        router.step()
    assert len(router.wan_restarts()) == 2


# ---------------------------------------------------------- notifications ---


def test_no_notifications_without_configuration(router: Router) -> None:
    setw(router, dnsmasq=False)
    router.run_until(lambda st: router.calls("dnsmasq-init") != [], max_steps=10)
    router.run_steps(3)
    assert router.telegrams() == []
    assert not (router.state_dir / "notify.queue").exists()


def test_wan_outage_is_reported_after_internet_returns(router: Router) -> None:
    telegram_on(router)  # Telegram blocked directly: goes through the VPN node
    setw(router, wan_up=False, wan_restart_fixes=True)
    router.run_until(lambda st: router.wan_restarts() != [], max_steps=10)
    assert router.telegrams() == []  # nothing is tried while the WAN is down
    router.run_until(lambda st: len(router.telegrams()) >= 3, max_steps=20)
    sent = [t for t in router.telegrams() if t["via"] == "a.example"]
    texts = [t["text"] for t in sent]
    assert texts[0].startswith("[TestRouter] ") and "Перезапускаю WAN" in texts[0]
    assert "Интернет восстановлен" in texts[1]
    assert not (router.state_dir / "notify.queue").read_text().strip()


def test_direct_telegram_is_used_when_it_works(router: Router) -> None:
    telegram_on(router, direct=True)
    setw(router, dnsmasq=False)
    router.run_until(lambda st: len(router.telegrams()) >= 1, max_steps=12)
    assert [t["via"] for t in router.telegrams()] == ["direct"]
    assert router.calls("sing-box-fetch") == []


def test_undeliverable_notifications_are_queued_and_capped(router: Router) -> None:
    telegram_on(router)
    router.set_node("a.example", isolated=False, live=True)  # no route to Telegram at all
    q = router.state_dir / "notify.queue"
    router.state_dir.mkdir(parents=True, exist_ok=True)
    q.write_text("".join(f"01.01 00:00 msg {i}\n" for i in range(29)))
    setw(router, dnsmasq=False)
    router.run_steps(12)
    lines = q.read_text().splitlines()
    assert 1 <= len(lines) <= 30 and lines[-1].endswith("Перезапустил dnsmasq.")
    assert router.logs().count("Telegram notification not delivered") == 1
    router.set_node("a.example", isolated=True, live=True)
    router.run_until(lambda st: not q.read_text().strip(), max_steps=30)
    assert "Telegram notifications delivered again" in router.logs()


def test_invalid_token_disables_notifications_without_leaking_it(router: Router) -> None:
    router.set_config(telegram_token="not a token " + TG_TOKEN[:5], telegram_chat_id="1")
    setw(router, dnsmasq=False)
    router.run_steps(6)
    assert router.telegrams() == []
    assert "telegram_token has an invalid format" in router.logs()
    assert "not a token" not in router.logs()


def test_notify_test_command(router: Router) -> None:
    telegram_on(router)
    out = router.cli("notify-test")
    assert out.stdout.strip() == "sent"
    assert "Проверка уведомлений" in router.telegrams()[-1]["text"]


def test_boot_is_reported(router: Router) -> None:
    telegram_on(router)
    router.set_time(15)
    router.step()
    router.run_steps(4)
    assert any("Роутер включился" in t["text"] for t in router.telegrams())


# -------------------------------------------------------------- event log ---


def test_important_events_go_to_a_capped_file(router: Router) -> None:
    router.set_config(event_log_max_kb="8")
    router.persist_dir.mkdir(parents=True, exist_ok=True)
    (router.persist_dir / "events.log").write_text("x" * 9000 + "\n")
    setw(router, dnsmasq=False)
    router.run_until(lambda st: router.calls("dnsmasq-init") != [], max_steps=10)
    assert (router.persist_dir / "events.log.1").exists()
    ev = router.events()
    assert len(ev) < 8 * 1024 and "warning router DNS unhealthy (DNSMASQ_DOWN)" in ev
    # Wall clock + uptime: readable even before NTP has synced after a boot.
    assert re.search(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d up=\d+s warning router DNS", ev, re.M)
    assert "boot grace" not in ev and "info " not in ev  # info level stays in syslog only
    out = router.cli("events", "5").stdout
    assert "restarting dnsmasq" in out


def test_event_log_can_be_disabled(router: Router) -> None:
    router.set_config(event_log="0")
    setw(router, dnsmasq=False)
    router.run_until(lambda st: router.calls("dnsmasq-init") != [], max_steps=10)
    assert router.events() == ""
