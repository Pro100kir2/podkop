# podkop-watchdog: diagnostics. Read-only: nothing here changes system state.
# shellcheck shell=sh disable=SC2034,SC2153 # globals are shared across sourced modules

podkop_get() { uci -q get "podkop.$1" 2>/dev/null; }

is_ipv4() {
	printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

# Direct resolver used for recovery traffic and candidate tests.
direct_dns() {
	_d=$C_DIRECT_DNS
	[ -z "$_d" ] && _d=$(podkop_get settings.bootstrap_dns_server)
	_d=${_d%%:*}
	is_ipv4 "$_d" || _d=77.88.8.8
	echo "$_d"
}

# Sets W_LINK (netifd says up), W_AUTO (0 = stopped on purpose with ifdown)
# and W_L3 (layer-3 device, e.g. pppoe-wan). Fails if the interface is unknown.
wan_status() {
	W_LINK=0 W_AUTO=1 W_L3=''
	_st=$(ubus call "network.interface.$C_WAN_INTERFACE" status 2>/dev/null) || return 1
	_f=$(printf '%s' "$_st" | jq -r '[.up, .autostart, (.l3_device // "")] | map(tostring) | join(" ")' 2>/dev/null) ||
		return 1
	# shellcheck disable=SC2086 # split the three fields
	set -- $_f
	[ "${1:-}" = true ] && W_LINK=1
	[ "${2:-}" = false ] && W_AUTO=0
	W_L3=${3:-}
	return 0
}

wan_link_up() { wan_status && [ "$W_LINK" = 1 ]; }

# ICMP to any target, or a direct DNS query (some ISPs filter ICMP).
internet_up() {
	for _t in $C_INTERNET_TARGET; do
		ping -c 1 -W 2 "$_t" >/dev/null 2>&1 && return 0
	done
	dns_ok "$(direct_dns)"
}

wan_ok() { wan_link_up && internet_up; }

wan_rx_bytes() { # device
	case "$1" in '' | */* | .*) return 1 ;; esac
	_f="$WD_SYS_NET/$1/statistics/rx_bytes"
	[ -r "$_f" ] || return 1
	_rx=''
	read -r _rx <"$_f" || return 1
	is_uint "$_rx" || return 1
	echo "$_rx"
}

dnsmasq_running() { pidof dnsmasq >/dev/null 2>&1; }

# One line per radio that is enabled in config:
#   <radio> <up> <pending> <autostart> <ifname,ifname|->
wifi_radios() {
	ubus call network.wireless status 2>/dev/null | jq -r '
		to_entries[] | select(.value.disabled != true)
		| ([.value.interfaces[]?.ifname // empty] | join(",")) as $i
		| "\(.key) \(.value.up) \(.value.pending) \(.value.autostart) \(if $i == "" then "-" else $i end)"' 2>/dev/null
}

# hostapd (AP) or wpa_supplicant (client) must be serving the interface.
wifi_daemon_ok() { # ifname
	ubus list "hostapd.$1" >/dev/null 2>&1 || ubus list "wpa_supplicant.$1" >/dev/null 2>&1
}

wifi_clients() { # ifname
	_wc=$(ubus call "hostapd.$1" get_clients 2>/dev/null | jq -r '.clients // {} | length' 2>/dev/null)
	is_uint "$_wc" && echo "$_wc" || echo 0
}

wifi_tx_packets() { # ifname
	case "$1" in '' | */* | .*) echo 0; return ;; esac
	_wt=''
	[ -r "$WD_SYS_NET/$1/statistics/tx_packets" ] && read -r _wt <"$WD_SYS_NET/$1/statistics/tx_packets"
	is_uint "$_wt" && echo "$_wt" || echo 0
}

# User intent: Podkop enabled at boot and not deliberately stopped.
podkop_intent_on() {
	"$WD_PODKOP_INIT" enabled >/dev/null 2>&1 || return 1
	[ "$(podkop_get settings.shutdown_correctly)" != 1 ]
}

singbox_running() { pidof sing-box >/dev/null 2>&1; }
podkop_nft_ok() { nft list table inet PodkopTable >/dev/null 2>&1; }

# Only the single-URL mode is rewritten by the watchdog.
podkop_mode_managed() {
	[ "$(podkop_get "$C_SEC.connection_type")" = proxy ] &&
		[ "$(podkop_get "$C_SEC.proxy_config_type")" = url ]
}

dns_ok() { # server
	nslookup "$C_DNS_TEST_DOMAIN" "$1" >/dev/null 2>&1
}

clash_addr() {
	if [ -n "$C_CLASH_API" ]; then
		echo "$C_CLASH_API"
		return
	fi
	_ip=$(ubus call network.interface.lan status 2>/dev/null |
		jq -r '."ipv4-address"[0].address // empty' 2>/dev/null)
	is_ipv4 "$_ip" || _ip=127.0.0.1
	echo "$_ip:9090"
}

# Writes a curl header file for the Clash API secret, if one is configured.
clash_auth_args() {
	_secret=''
	[ "$(podkop_get settings.enable_yacd)" = 1 ] && _secret=$(podkop_get settings.yacd_secret_key)
	if [ -n "$_secret" ]; then
		printf 'Authorization: Bearer %s\n' "$_secret" | write_atomic "$TMP_DIR/clash.hdr"
		echo "-H @$TMP_DIR/clash.hdr"
	fi
}

# Real HTTP request through Podkop's active outbound, via the Clash API.
# Prints ok | fail | unknown (API unreachable or outbound tag not found).
node_check() {
	_addr=$(clash_addr)
	_auth=$(clash_auth_args)
	_tag="$C_SEC-out"
	_max=$((C_TUNNEL_TEST_TIMEOUT_MS / 1000 + 3))
	_seen_reply=0
	for _u in $C_TUNNEL_TEST_URL; do
		# shellcheck disable=SC2086 # _auth is either empty or one safe word pair
		_code=$(curl -s -m "$_max" -G $_auth \
			--data-urlencode "url=$_u" --data-urlencode "timeout=$C_TUNNEL_TEST_TIMEOUT_MS" \
			-o "$TMP_DIR/clash.out" -w '%{http_code}' \
			"http://$_addr/proxies/$_tag/delay" 2>/dev/null)
		_rc=$?
		rm -f "$TMP_DIR/clash.hdr"
		[ "$_rc" -ne 0 ] && continue
		[ "$_code" = 404 ] && continue
		_seen_reply=1
		if [ "$_code" = 200 ]; then
			_delay=$(jq -r '.delay // empty' "$TMP_DIR/clash.out" 2>/dev/null)
			if is_uint "$_delay" && [ "$_delay" -gt 0 ]; then
				rm -f "$TMP_DIR/clash.out"
				echo ok
				return
			fi
		fi
	done
	rm -f "$TMP_DIR/clash.out"
	[ "$_seen_reply" = 1 ] && echo fail || echo unknown
}

# Full path: local DNS (fakeip) + nft marks + tproxy + tunnel. Podkop routes
# ip.podkop.fyi through the main outbound; the body is the exit IP.
full_path_ok() {
	# Same endpoint Podkop's LuCI page uses: /check returns {"fakeip":..,"IP":"<exit ip>"}
	# (the bare root URL is a 404).
	_b=$(curl -s --proto '=https' -m 10 "$C_FULL_PATH_URL" 2>/dev/null) || return 1
	_ip=$(printf '%s' "$_b" | jq -r '.IP // empty' 2>/dev/null)
	printf '%s' "$_ip" | grep -Eq '^[0-9a-fA-F.:]+$' && printf '%s' "$_ip" | grep -q '[.:]'
}

# Combined tunnel verdict. Prints ok | fail | unknown.
tunnel_state() { # dns_local_ok(1/0)
	_n=$(node_check)
	if [ "$_n" = unknown ] && [ "$1" = 1 ]; then
		full_path_ok && _n=ok || _n=fail
	fi
	echo "$_n"
}

# Sets D_* variables and D_CLASS. See docs/DESIGN.md for precedence.
# Router-level faults (dnsmasq, WAN) are classified first and independently
# of Podkop: Podkop is one part of the router, not the whole of it.
diagnose() {
	D_WAN=0 D_INET=0 D_INTENT=0 D_SB=0 D_NFT=0 D_DNS=0 D_DNS_PK=- D_DNS_DIRECT=-
	D_NODE=- D_PATH=- D_DNSMASQ=0
	if [ "${W_CHECKED:-0}" = 1 ]; then
		# Already probed by wan_watch in this tick.
		D_WAN=$W_LINK D_INET=$W_INET
	else
		wan_link_up && D_WAN=1
		[ "$D_WAN" = 1 ] && internet_up && D_INET=1
	fi
	dnsmasq_running && D_DNSMASQ=1
	podkop_intent_on && D_INTENT=1
	singbox_running && D_SB=1
	podkop_nft_ok && D_NFT=1

	if [ "$D_DNSMASQ" = 0 ]; then
		# The router's DNS server (used by every LAN client) is not running.
		D_CLASS=DNSMASQ_DOWN
	elif [ "$D_WAN" = 0 ] || [ "$D_INET" = 0 ]; then
		D_CLASS=WAN_DOWN
	elif [ "$D_INTENT" = 0 ]; then
		# Podkop is off on purpose; the router's own DNS must still answer.
		dns_ok 127.0.0.1 && D_DNS=1
		if [ "$D_DNS" = 1 ]; then
			D_CLASS=PODKOP_OFF
		else
			dns_ok "$(direct_dns)" && D_DNS_DIRECT=1 || D_DNS_DIRECT=0
			if [ "$D_DNS_DIRECT" = 1 ]; then D_CLASS=DNSMASQ_BROKEN; else D_CLASS=DNS_UPSTREAM_DOWN; fi
		fi
	elif [ "$D_SB" = 0 ] || [ "$D_NFT" = 0 ]; then
		D_CLASS=PODKOP_DOWN
	else
		dns_ok 127.0.0.1 && D_DNS=1
		if [ "$D_DNS" = 0 ]; then
			if [ "$(podkop_get settings.dns_type)" = udp ]; then
				_pk=$(podkop_get settings.dns_server)
				_pk=${_pk%%:*}
				if is_ipv4 "$_pk"; then
					dns_ok "$_pk" && D_DNS_PK=1 || D_DNS_PK=0
				fi
			fi
			dns_ok "$(direct_dns)" && D_DNS_DIRECT=1 || D_DNS_DIRECT=0
		fi
		D_NODE=$(tunnel_state "$D_DNS")
		if [ "$D_NODE" = ok ] && [ "$D_DNS" = 1 ] && [ "$C_CHECK_FULL_PATH" = 1 ]; then
			full_path_ok && D_PATH=1 || D_PATH=0
		fi

		if [ "$D_DNS" = 0 ] && { [ "$D_DNS_PK" = 0 ] || { [ "$D_DNS_PK" = - ] && [ "$D_DNS_DIRECT" = 0 ]; }; }; then
			# Podkop's own upstream resolver is unreachable: not fixable by a restart or node switch.
			D_CLASS=DNS_UPSTREAM_DOWN
		elif [ "$D_NODE" = fail ]; then
			D_CLASS=TUNNEL_DOWN
		elif [ "$D_DNS" = 0 ]; then
			D_CLASS=DNS_CHAIN_DOWN
		elif [ "$D_PATH" = 0 ]; then
			D_CLASS=PATH_DOWN
		elif [ "$D_NODE" = unknown ]; then
			D_CLASS=TUNNEL_UNKNOWN
		else
			D_CLASS=HEALTHY
		fi
	fi
	S_D_SUMMARY="class=$D_CLASS,wan=$D_WAN,inet=$D_INET,podkop=$D_INTENT,singbox=$D_SB,nft=$D_NFT,dns=$D_DNS,dns_podkop=$D_DNS_PK,dns_direct=$D_DNS_DIRECT,dnsmasq=$D_DNSMASQ,node=$D_NODE,path=$D_PATH"
}
