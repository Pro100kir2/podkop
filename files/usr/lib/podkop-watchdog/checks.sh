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

# Interface that is up and owns the default route (lowest metric). "lan" is
# excluded: a dumb access point has a gateway but no WAN.
wan_detect_active() {
	ubus_t call network.interface dump 2>/dev/null | jq -r '
		(.interface // []) | map(select(.interface != "loopback" and .interface != "lan"
			and ((.proto // "") | IN("wireguard","amneziawg","openvpn","vpnc","gre","gretap","vxlan","none") | not))) as $i
		| [ $i[] | select(.up == true and ((.route // []) | any(.target == "0.0.0.0" and .mask == 0))) ]
		| sort_by(.metric // 0) | .[0].interface // empty' 2>/dev/null
}

# Best guess while nothing owns a default route (the WAN is down right now): an
# interface called "wan", else a modem/PPPoE/DHCP one. Empty when the LAN itself
# holds the default route (access-point mode: there is no WAN to repair).
# (No regex functions: OpenWrt's default jq is built without oniguruma.)
wan_detect_guess() {
	ubus_t call network.interface dump 2>/dev/null | jq -r '
		(.interface // []) as $all
		| ($all | map(select(.interface == "lan" and .up == true and ((.route // []) | any(.target == "0.0.0.0" and .mask == 0)))) | length) as $lan_gw
		| if $lan_gw > 0 then empty else
		  ($all | map(select(.interface != "loopback" and .interface != "lan"
			and ((.proto // "") | IN("wireguard","amneziawg","openvpn","vpnc","gre","gretap","vxlan","none") | not)))) as $i
		  | ( [ $i[] | select(.interface == "wan") ] | .[0].interface )
		    // ( [ $i[] | select((.proto // "") | IN("pppoe","dhcp","qmi","ncm","mbim","modemmanager","3g","wwan","l2tp","pptp")) ]
		         | map(select(.interface | endswith("6") | not)) | .[0].interface )
		    // empty end' 2>/dev/null
}

# Sets WAN_IF: the configured name, else the remembered one, else detected.
# Only an interface that actually carries the default route is remembered; a
# guess is re-evaluated on every tick (once per tick: W_TRIED).
wan_resolve() {
	WAN_IF=$C_WAN_INTERFACE
	[ -n "$WAN_IF" ] && return 0
	WAN_IF=${S_WAN_IF:-}
	[ -n "$WAN_IF" ] && return 0
	if [ "${W_TRIED:-0}" = 1 ]; then
		WAN_IF=${W_GUESS:-}
		return 0
	fi
	W_TRIED=1
	WAN_IF=$(wan_detect_active)
	if [ -n "$WAN_IF" ]; then
		S_WAN_IF=$WAN_IF
		log notice "WAN interface auto-detected: $WAN_IF"
	else
		WAN_IF=$(wan_detect_guess)
	fi
	W_GUESS=$WAN_IF
	return 0
}

wan_parse() { # status json -> W_LINK W_AUTO W_L3
	W_LINK=0 W_AUTO=1 W_L3=''
	_f=$(printf '%s' "$1" | jq -r '[.up, .autostart, (.l3_device // "")] | map(tostring) | join(" ")' 2>/dev/null) ||
		return 1
	# shellcheck disable=SC2086 # split the three fields
	set -- $_f
	[ "${1:-}" = true ] && W_LINK=1
	[ "${2:-}" = false ] && W_AUTO=0
	W_L3=${3:-}
	return 0
}

# Sets W_LINK (netifd says up), W_AUTO (0 = stopped on purpose with ifdown),
# W_L3 (layer-3 device, e.g. pppoe-wan) and W_UNKNOWN (1 = no such interface or
# netifd did not answer: the caller must judge connectivity by the probes alone).
wan_status() {
	W_LINK=0 W_AUTO=1 W_L3='' W_UNKNOWN=0
	_st=''
	_urc=0
	if [ -n "$WAN_IF" ]; then
		_st=$(ubus_t call "network.interface.$WAN_IF" status 2>/dev/null)
		_urc=$?
		if [ -z "$_st" ] && [ "$_urc" = 4 ] && [ -z "$C_WAN_INTERFACE" ] && [ -n "$S_WAN_IF" ]; then
			# The remembered interface is gone (rc 4 = not found; a busy netifd
			# gives a timeout instead and must not make us forget it).
			S_WAN_IF='' W_TRIED=0
			wan_resolve
			[ -n "$WAN_IF" ] && _st=$(ubus_t call "network.interface.$WAN_IF" status 2>/dev/null)
		fi
	fi
	if [ -z "$_st" ] || ! wan_parse "$_st"; then
		W_LINK=0 W_AUTO=1 W_L3='' W_UNKNOWN=1
		return 1
	fi
	if [ "$W_LINK" = 0 ] && [ -z "$C_WAN_INTERFACE" ] && [ "${W_TRIED:-0}" = 0 ]; then
		# A down interface may simply be the wrong one (travel router, mwan3).
		W_TRIED=1
		_alt=$(wan_detect_active)
		if [ -n "$_alt" ] && [ "$_alt" != "$WAN_IF" ]; then
			log notice "WAN interface changed: $WAN_IF -> $_alt"
			S_WAN_IF=$_alt WAN_IF=$_alt
			_st=$(ubus_t call "network.interface.$WAN_IF" status 2>/dev/null)
			wan_parse "$_st" || {
				W_UNKNOWN=1
				return 1
			}
		fi
	fi
	return 0
}

# Without a known WAN interface only the internet probes can tell.
wan_link_up() { if wan_status; then [ "$W_LINK" = 1 ]; else [ "$W_UNKNOWN" = 1 ]; fi; }

# ICMP to any target, or a direct DNS query (some ISPs filter ICMP).
internet_up() {
	for _t in $C_INTERNET_TARGET; do
		run_with_timeout 4 ping -c 1 -W 2 "$_t" >/dev/null 2>&1 && return 0
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

# dnsmasq is ours to repair only if the user left it enabled: with AdGuard Home,
# smartdns etc. it is disabled on purpose and starting it would fight for :53.
dnsmasq_managed() { "$WD_DNSMASQ_INIT" enabled >/dev/null 2>&1; }

# 1 = dnsmasq running, 0 = dead and DNS silent (repair), 2 = not ours or
# something else answers on 127.0.0.1 (leave it alone).
dnsmasq_state() {
	if dnsmasq_running; then echo 1; return; fi
	if ! dnsmasq_managed; then echo 2; return; fi
	if dns_ok 127.0.0.1; then echo 2; return; fi
	echo 0
}

# One line per radio that is enabled in config:
#   <radio> <up> <pending> <autostart> <ifname,ifname|->
wifi_radios() {
	ubus_t call network.wireless status 2>/dev/null | jq -r '
		to_entries[] | select(.value.disabled != true)
		| ([.value.interfaces[]? | select((.config.mode // "ap") | IN("ap","sta")) | .ifname // empty] | join(",")) as $i
		| "\(.key) \(.value.up) \(.value.pending) \(.value.autostart) \(if $i == "" then "-" else $i end)"' 2>/dev/null
}

# hostapd (AP) or wpa_supplicant (client) must be serving the interface.
wifi_daemon_ok() { # ifname
	ubus_t list "hostapd.$1" >/dev/null 2>&1 || ubus_t list "wpa_supplicant.$1" >/dev/null 2>&1
}

wifi_clients() { # ifname
	_wc=$(ubus_t call "hostapd.$1" get_clients 2>/dev/null | jq -r '.clients // {} | length' 2>/dev/null)
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
# Terse listing (no set elements: Podkop's subnet sets are huge and would be
# printed in full every 30 s); nft versions without -t fall back to the full one.
podkop_nft_ok() {
	nft -t list table inet PodkopTable >/dev/null 2>&1 || nft list table inet PodkopTable >/dev/null 2>&1
}

# Only the single-URL mode is rewritten by the watchdog.
podkop_mode_managed() {
	[ "$(podkop_get "$C_SEC.connection_type")" = proxy ] &&
		[ "$(podkop_get "$C_SEC.proxy_config_type")" = url ]
}

dns_ok() { # server
	run_with_timeout 5 nslookup "$C_DNS_TEST_DOMAIN" "$1" >/dev/null 2>&1
}

# Field of the sing-box config Podkop generated (empty if unreadable).
singbox_field() { # jq filter
	[ -r "$WD_SINGBOX_CONFIG" ] || return 0
	jq -r "$1 // empty" "$WD_SINGBOX_CONFIG" 2>/dev/null
}

# Clash API address: configured, else what Podkop's own sing-box config says,
# else <LAN IP>:9090. A wildcard bind address is replaced by the LAN IP.
clash_addr() {
	if [ -n "$C_CLASH_API" ]; then
		echo "$C_CLASH_API"
		return
	fi
	_ip=$(ubus_t call network.interface.lan status 2>/dev/null |
		jq -r '."ipv4-address"[0].address // empty' 2>/dev/null)
	is_ipv4 "$_ip" || _ip=127.0.0.1
	_ec=$(singbox_field '.experimental.clash_api.external_controller')
	if printf '%s' "$_ec" | grep -Eq '^[A-Za-z0-9.:-]*:[0-9]{1,5}$'; then
		_eh=${_ec%:*}
		case "$_eh" in '' | 0.0.0.0 | '::' | '[::]') _eh=$_ip ;; esac
		echo "$_eh:${_ec##*:}"
		return
	fi
	echo "$_ip:9090"
}

# Outbound tag of the active node: Podkop's "<section>-out" unless its generated
# config names it differently.
clash_tag() {
	_ct="$C_SEC-out"
	_tags=$(singbox_field '[.outbounds[]?.tag] | join(" ")')
	if [ -n "$_tags" ] && ! in_list "$_ct" "$_tags"; then
		for _t in $_tags; do
			case "$_t" in "$C_SEC-out"*) _ct=$_t; break ;; esac
		done
	fi
	printf '%s' "$_ct" | grep -Eq '^[A-Za-z0-9_.-]+$' || _ct="$C_SEC-out"
	echo "$_ct"
}

# Writes a curl header file for the Clash API secret, if one is configured.
clash_auth_args() {
	_secret=''
	[ "$(podkop_get settings.enable_yacd)" = 1 ] && _secret=$(podkop_get settings.yacd_secret_key)
	[ -n "$_secret" ] || _secret=$(singbox_field '.experimental.clash_api.secret')
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
	_tag=$(clash_tag)
	_max=$((C_TUNNEL_TEST_TIMEOUT_MS / 1000 + 3))
	_seen_reply=0
	for _u in $C_TUNNEL_TEST_URL; do
		# shellcheck disable=SC2086 # _auth is either empty or one safe word pair
		_code=$(curl -s -m "$_max" -G $_auth \
			--data-urlencode "url=$_u" --data-urlencode "timeout=$C_TUNNEL_TEST_TIMEOUT_MS" \
			-o "$TMP_DIR/clash.out" -w '%{http_code}' \
			"http://$_addr/proxies/$_tag/delay" 2>/dev/null)
		_rc=$?
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
	rm -f "$TMP_DIR/clash.out" "$TMP_DIR/clash.hdr"
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

# Tunnel verdict from the real request through Podkop's own outbound:
# ok | fail | unknown. "unknown" (Clash unreachable or the tag not found, e.g.
# after a Podkop update) must never be turned into "fail" by a third-party probe:
# that would switch a working node.
tunnel_state() {
	node_check
}

# Sets D_* variables and D_CLASS. See docs/DESIGN.md for precedence.
# Router-level faults (dnsmasq, WAN) are classified first and independently
# of Podkop: Podkop is one part of the router, not the whole of it.
diagnose() {
	D_WAN=0 D_INET=0 D_INTENT=0 D_SB=0 D_NFT=0 D_DNS=0 D_DNS_PK=- D_DNS_DIRECT=-
	D_NODE=- D_PATH=- D_DNSMASQ=0
	wan_resolve
	if [ "${W_CHECKED:-0}" = 1 ]; then
		# Already probed by wan_watch in this tick.
		D_WAN=$W_LINK D_INET=$W_INET
		[ "$W_INET" = 1 ] && D_WAN=1
	else
		wan_link_up && D_WAN=1
		# With an auto-detected interface a "down" link may just be the wrong
		# interface: working internet always wins.
		if [ "$D_WAN" = 1 ] || [ -z "$C_WAN_INTERFACE" ]; then
			internet_up && D_INET=1 D_WAN=1
		fi
	fi
	D_DNSMASQ=$(dnsmasq_state)
	podkop_intent_on && D_INTENT=1
	singbox_running && D_SB=1
	podkop_nft_ok && D_NFT=1

	if [ "$D_DNSMASQ" = 0 ]; then
		# dnsmasq (used by every LAN client) is enabled but dead and DNS is silent.
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
		D_NODE=$(tunnel_state)
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
