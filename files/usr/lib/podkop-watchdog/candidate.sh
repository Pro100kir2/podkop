# podkop-watchdog: isolated candidate tests and Podkop configuration changes.
# shellcheck shell=sh disable=SC2034 # globals are shared across sourced modules

lkg_file() {
	if [ "$C_PERSIST_LKG" = 1 ]; then echo "$WD_PERSIST_DIR/lkg"; else echo "$WD_STATE_DIR/lkg"; fi
}

lkg_get() { cat "$(lkg_file)" 2>/dev/null; }

# Written only when it changes (flash wear).
lkg_set() { # url
	_f=$(lkg_file)
	[ "$(lkg_get)" = "$1" ] && return 0
	mkdir -p "${_f%/*}" && chmod 700 "${_f%/*}"
	printf '%s\n' "$1" | write_atomic "$_f"
}

current_proxy() { podkop_get "$C_SEC.proxy_string"; }

same_node() { [ "${1%%#*}" = "${2%%#*}" ]; }

# Build a minimal sing-box config holding only the candidate outbound, using
# Podkop's own URL parser so the outbound matches what Podkop would generate.
build_test_config() { # url outfile
	_raw="$TMP_DIR/outbound.json"
	(
		set +u # Podkop's library is not set -u safe
		# Podkop's helpers call log "message" "level"; silence them so nothing
		# derived from the URL can reach syslog.
		# shellcheck disable=SC2329 # invoked by the sourced Podkop library
		log() { :; }
		# shellcheck disable=SC1091
		. "$WD_PODKOP_LIB/sing_box_config_facade.sh" >/dev/null 2>&1 || exit 90
		command -v sing_box_cf_add_proxy_outbound >/dev/null 2>&1 || exit 91
		sing_box_cf_add_proxy_outbound '{"outbounds":[]}' wdtest "$1" 0
	) >"$_raw" 2>/dev/null
	_rc=$?
	if [ "$_rc" -ne 0 ] || [ ! -s "$_raw" ]; then
		rm -f "$_raw"
		[ "$_rc" -ge 90 ] && log err "Podkop URL parser not available ($WD_PODKOP_LIB)"
		return 1
	fi
	# routing_mark: Podkop's nft output chain returns early for this mark, so the
	# test can never be captured by the (possibly broken) live tunnel.
	jq -c --arg dns "$(direct_dns)" --argjson mark "$PODKOP_OUTBOUND_MARK" '
		(.outbounds // []) as $o
		| if ($o | length) != 1 then error("expected one outbound") else . end
		| {log: {level: "error"},
		   dns: {servers: [{type: "udp", tag: "wd-dns", server: $dns}]},
		   outbounds: [$o[0] + {routing_mark: $mark}],
		   route: {default_domain_resolver: "wd-dns"}}' "$_raw" >"$2" 2>/dev/null
	_rc=$?
	rm -f "$_raw"
	return "$_rc"
}

# Prints a short reason when the failover cannot work with the installed
# Podkop/sing-box, nothing when it can. Never touches the running Podkop.
compat_probe() {
	command -v sing-box >/dev/null 2>&1 || { echo no_singbox; return; }
	command -v jq >/dev/null 2>&1 || { echo no_jq; return; }
	_sv=$(sing-box version 2>/dev/null | sed -n 's/^sing-box version \([0-9]*\)\.\([0-9]*\).*/\1 \2/p' | head -n 1)
	if [ -n "$_sv" ]; then
		# shellcheck disable=SC2086 # two numbers
		set -- $_sv
		if [ "$1" -lt 1 ] || { [ "$1" -eq 1 ] && [ "$2" -lt 12 ]; }; then echo "singbox_$1.$2_lt_1.12"; return; fi
	fi
	[ -r "$WD_PODKOP_LIB/sing_box_config_facade.sh" ] || { echo no_podkop_parser; return; }
	podkop_mode_managed || return 0 # nothing to switch in this mode
	_cu=$(current_proxy)
	[ -n "$_cu" ] || return 0
	_pcfg="$TMP_DIR/compat.json"
	if build_test_config "$_cu" "$_pcfg"; then
		rm -f "$_pcfg"
		return 0
	fi
	rm -f "$_pcfg"
	# The active node itself may be malformed: only a parser that also rejects
	# the last-known-good node counts as incompatible.
	_cl=$(lkg_get)
	if [ -n "$_cl" ] && ! same_node "$_cl" "$_cu" && build_test_config "$_cl" "$_pcfg"; then
		rm -f "$_pcfg"
		return 0
	fi
	rm -f "$_pcfg"
	echo podkop_parser_changed
}

# test_candidate URL -> 0 pass, 1 fail. Sets T_REASON.
# Never touches the running Podkop instance.
test_candidate() {
	T_REASON=''
	_cfg="$TMP_DIR/test.json"
	_body="$TMP_DIR/test.body"
	if ! build_test_config "$1" "$_cfg"; then
		T_REASON=parse
		return 1
	fi
	_tag=$(jq -r '.outbounds[0].tag' "$_cfg" 2>/dev/null)
	if ! sing-box check -c "$_cfg" >/dev/null 2>&1; then
		rm -f "$_cfg"
		T_REASON=invalid
		return 1
	fi
	_pass=0
	while [ "$_pass" -lt "$C_CANDIDATE_TEST_PASSES" ]; do
		rm -f "$_body"
		# oom_score_adj 1000: if memory runs out, the kernel kills the test, not Podkop.
		# shellcheck disable=SC2016 # positional args are expanded by the inner sh
		run_with_timeout "$C_CANDIDATE_TEST_TIMEOUT" sh -c \
			'echo 1000 >/proc/self/oom_score_adj 2>/dev/null; exec sing-box tools fetch -c "$1" -D "$2" -o "$3" "$4"' \
			_ "$_cfg" "$TMP_DIR" "$_tag" "$C_CANDIDATE_TEST_URL" >"$_body" 2>/dev/null
		_rc=$?
		if [ "$_rc" -ne 0 ] || ! grep -qF -- "$C_CANDIDATE_EXPECT" "$_body"; then
			T_REASON="fetch(rc=$_rc,pass=$_pass)"
			break
		fi
		_pass=$((_pass + 1))
	done
	rm -f "$_cfg" "$_body"
	[ "$_pass" -ge "$C_CANDIDATE_TEST_PASSES" ]
}

# Reload runs detached and bounded (see svc_run): a hung reload must not freeze
# WAN/Wi-Fi repair and notifications, and is never killed (it may hold nft).
podkop_reload() {
	svc_run podkop "$C_SERVICE_TIMEOUT" "$WD_PODKOP_INIT" reload
	_prc=$?
	svc_hung podkop "$_prc"
	return "$_prc"
}

# One notice per hang; cleared when the action finishes again.
svc_hung() { # name rc
	case "$2" in
	124 | 125)
		if [ "$S_HUNG_NOTE" != "$1" ]; then
			log err "$1 action is not finishing (over ${C_SERVICE_TIMEOUT}s); no new one is started until it ends"
			notify "Команда управления службой $1 зависла. Новые перезапуски отложены, пока она не завершится."
			S_HUNG_NOTE=$1
		fi
		;;
	*) [ "$S_HUNG_NOTE" = "$1" ] && S_HUNG_NOTE='' ;; # it finished, however it ended
	esac
	return 0
}

podkop_has_staged_changes() {
	[ -n "$(uci -q changes podkop 2>/dev/null)" ]
}

# Set proxy_string through uci + Podkop's normal reload. Returns 1 on uci error,
# 2 on reload error.
podkop_set_proxy() { # url
	uci -q set "podkop.$C_SEC.proxy_string=$1" || return 1
	uci -q commit podkop || {
		uci -q revert "podkop.$C_SEC.proxy_string" 2>/dev/null
		return 1
	}
	podkop_reload || return 2
	return 0
}
