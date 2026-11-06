# podkop-watchdog: event log and Telegram notifications.
# shellcheck shell=sh disable=SC2034,SC2153 # globals are shared across sourced modules

NOTIFY_QUEUE="$WD_STATE_DIR/notify.queue"
NOTIFY_QUEUE_MAX=30

# ------------------------------------------------------------- event log ---

# Important events (notice and above) also go to a small file, because syslog
# is a RAM ring buffer that sing-box can flood during outages. Size-capped:
# at most two files of event_log_max_kb each. Each line carries the uptime:
# the router has no RTC, so until NTP syncs the wall clock is only the time
# of the newest file in /etc (sysfixtime).
event_write() { # level message
	[ "${C_EVENT_LOG:-1}" = 1 ] || return 0
	_ef=$WD_EVENT_LOG
	[ -n "$_ef" ] || return 0
	# Flash wear: the same message within 5 minutes (a flapping check) is not
	# written again. The last few messages are remembered in tmpfs.
	_ek="$WD_STATE_DIR/event.recent"
	_en=$(now_s)
	if [ -f "$_ek" ] && EV_MSG="$2" awk -v n="$_en" '
		{ ts = $1; sub(/^[0-9]+ /, "") }
		$0 == ENVIRON["EV_MSG"] && n >= ts && n - ts < 300 { f = 1 }
		END { exit !f }' "$_ek"; then
		return 0
	fi
	if [ -d "$WD_STATE_DIR" ]; then
		{ tail -n 15 "$_ek" 2>/dev/null; printf '%s %s\n' "$_en" "$2"; } >"$_ek.new" 2>/dev/null &&
			mv -f "$_ek.new" "$_ek" 2>/dev/null
	fi
	[ -d "${_ef%/*}" ] || (umask 077 && mkdir -p "${_ef%/*}") 2>/dev/null || return 0
	(umask 077 && printf '%s up=%ss %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$(now_s)" "$1" "$2" >>"$_ef") 2>/dev/null || return 0
	_esz=$(wc -c <"$_ef" 2>/dev/null) || return 0
	if [ "${_esz:-0}" -gt $((${C_EVENT_LOG_MAX_KB:-64} * 1024)) ]; then
		mv -f "$_ef" "$_ef.1" 2>/dev/null
	fi
	return 0
}

# --------------------------------------------------------- notifications ---

notify_enabled() { [ "$C_NOTIFY" = 1 ] && [ -n "$C_TG_TOKEN" ] && [ -n "$C_TG_CHAT" ]; }

# Queue a message (Russian, for the owner). Never include URLs, UUIDs or hosts.
notify() { # text
	notify_enabled || return 0
	_nl=$(printf '%s' "$1" | tr '\n' ' ' | cut -c1-400)
	[ -n "$_nl" ] || return 0
	# Drop an exact repeat of the last queued message.
	[ -s "$NOTIFY_QUEUE" ] && [ "$(tail -n 1 "$NOTIFY_QUEUE" | cut -d' ' -f3-)" = "$_nl" ] && return 0
	(umask 077 && printf '%s %s\n' "$(date '+%d.%m %H:%M')" "$_nl" >>"$NOTIFY_QUEUE") 2>/dev/null || return 0
	if [ "$(wc -l <"$NOTIFY_QUEUE")" -gt "$NOTIFY_QUEUE_MAX" ]; then
		tail -n "$NOTIFY_QUEUE_MAX" "$NOTIFY_QUEUE" | write_atomic "$NOTIFY_QUEUE"
	fi
}

tg_ok() { [ "$(printf '%s' "$1" | jq -r '.ok // false' 2>/dev/null)" = true ]; }

router_name() {
	_rn=$(cat "$WD_HOSTNAME_FILE" 2>/dev/null)
	echo "${_rn:-router}"
}

# Telegram is often blocked directly, so try: direct HTTPS, then through the
# active node, then through the last-known-good node (isolated sing-box, the
# same mechanism as candidate tests; the live tunnel is never used).
tg_send() { # text
	_tq=$(jq -rn --arg c "$C_TG_CHAT" --arg t "$1" '"chat_id=\($c | @uri)&text=\($t | @uri)"' 2>/dev/null) ||
		return 1
	_turl="https://api.telegram.org/bot$C_TG_TOKEN/sendMessage?$_tq"
	# The URL (it holds the token) goes to curl via stdin, not argv.
	_tr=$(printf 'url = "%s"\n' "$_turl" |
		curl -s --proto '=https' --tlsv1.2 -m 8 --max-filesize 65536 -K - 2>/dev/null) && tg_ok "$_tr" && return 0
	[ "$(mem_available_kb)" -ge "$C_MIN_MEM_AVAILABLE_KB" ] || return 1
	# A sing-box start costs RAM and CPU: at most one round of attempts per 10 min
	# (the notify-test command ignores the limit).
	_tvn=$(now_s)
	if [ "${NOTIFY_FORCE_VIA:-0}" != 1 ] && [ "$S_TG_VIA_AT" -gt "$_tvn" ]; then
		return 1
	fi
	_tcfg="$TMP_DIR/tg.json"
	_tprev=''
	for _tnode in "$(current_proxy)" "$(lkg_get)"; do
		[ -n "$_tnode" ] || continue
		[ -n "$_tprev" ] && same_node "$_tnode" "$_tprev" && continue
		_tprev=$_tnode
		build_test_config "$_tnode" "$_tcfg" || continue
		_tr=$(run_with_timeout 15 sing-box tools fetch -c "$_tcfg" -D "$TMP_DIR" -o wdtest-out "$_turl" 2>/dev/null)
		rm -f "$_tcfg"
		tg_ok "$_tr" && return 0
	done
	# Only a failed round closes the window: while the route works, every
	# queued message goes out at once.
	S_TG_VIA_AT=$((_tvn + 600))
	return 1
}

# Deliver queued messages; at most once a minute and only while the WAN works.
notify_flush() {
	[ -s "$NOTIFY_QUEUE" ] || return 0
	if ! notify_enabled; then
		rm -f "$NOTIFY_QUEUE"
		return 0
	fi
	_fnow=$(now_s)
	[ "$S_NOTIFY_AT" -gt "$_fnow" ] && return 0
	S_NOTIFY_AT=$((_fnow + 60))
	[ "$S_WAN_FAIL_N" = 0 ] && [ "$S_LAST_CLASS" != WAN_DOWN ] || return 0
	exec 8>"$WD_LOCK_FILE.test"
	if ! flock -n 8; then
		exec 8>&-
		return 0
	fi
	_fname=$(router_name)
	_fsent=0
	while [ "$_fsent" -lt 5 ] && [ -s "$NOTIFY_QUEUE" ]; do
		_fmsg=$(head -n 1 "$NOTIFY_QUEUE")
		if ! tg_send "[$_fname] $_fmsg"; then
			S_NOTIFY_FAILS=$((S_NOTIFY_FAILS + 1))
			[ "$S_NOTIFY_FAILS" = 1 ] && log warning "Telegram notification not delivered; retrying with growing pauses"
			# Pause 2, 4, ... 60 min after consecutive failures.
			_fb=3600
			[ "$S_NOTIFY_FAILS" -le 5 ] && _fb=$((60 << S_NOTIFY_FAILS))
			[ "$_fb" -gt 3600 ] && _fb=3600
			S_NOTIFY_AT=$((_fnow + _fb))
			break
		fi
		[ "$S_NOTIFY_FAILS" -gt 0 ] && log info "Telegram notifications delivered again"
		S_NOTIFY_FAILS=0
		tail -n +2 "$NOTIFY_QUEUE" | write_atomic "$NOTIFY_QUEUE"
		_fsent=$((_fsent + 1))
	done
	exec 8>&-
	return 0
}
