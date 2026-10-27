# podkop-watchdog: recovery state machine. One bounded step per tick.
# Every state sets DELAY (seconds until the next tick). Nothing here sleeps.
# shellcheck shell=sh disable=SC2034,SC2153 # globals are shared across sourced modules

note_once() { # key level message   -- log only when the note changes
	if [ "$S_NOTE" != "$1" ]; then
		log "$2" "$3"
		S_NOTE=$1
	fi
}

in_list() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }

# ------------------------------------------------------------- monitoring ---

st_monitor() {
	diagnose
	_now=$(now_s)
	if [ "$D_INET" = 1 ] && [ $((_now - S_LAST_API_AT)) -ge "$C_API_CHECK_INTERVAL" ]; then
		S_LAST_API_AT=$_now
		_was=$S_API_OK
		if api_req GET /health && [ "$(json_field status)" = ok ]; then S_API_OK=1; else S_API_OK=0; fi
		rm -f "$API_BODY"
		if [ "$_was" != "$S_API_OK" ]; then
			if [ "$S_API_OK" = 1 ]; then log info "API reachable"; else log warning "API unreachable ($(api_err_desc))"; fi
		fi
	fi

	if [ "$D_CLASS" != "$S_LAST_CLASS" ]; then
		case "$D_CLASS" in
		HEALTHY) log notice "status: $S_D_SUMMARY" ;;
		*) log warning "status: $S_D_SUMMARY" ;;
		esac
		S_NOTE=''
	fi
	S_LAST_CLASS=$D_CLASS

	case "$D_CLASS" in
	HEALTHY | TUNNEL_UNKNOWN)
		S_FAIL_N=0 S_PK_FAIL_N=0 S_DNS_ESC=0
		S_OK_N=$((S_OK_N + 1))
		if [ "$D_CLASS" = HEALTHY ] && [ "$S_OK_N" -ge "$C_TUNNEL_OK_THRESHOLD" ] && podkop_mode_managed; then
			_cur=$(current_proxy)
			[ -n "$_cur" ] && lkg_set "$_cur"
		fi
		;;
	PODKOP_OFF | WAN_DOWN | DNS_UPSTREAM_DOWN | PATH_DOWN)
		# Not fixable by a node switch or Podkop restart (PATH_DOWN depends on
		# the third-party ip.podkop.fyi service): report only. A dead WAN is
		# handled separately by wan_watch.
		S_FAIL_N=0 S_PK_FAIL_N=0 S_OK_N=0
		;;
	TUNNEL_DOWN)
		S_OK_N=0 S_PK_FAIL_N=0
		S_FAIL_N=$((S_FAIL_N + 1))
		[ "$S_FAIL_N" -ge "$C_TUNNEL_FAIL_THRESHOLD" ] && start_recovery
		;;
	PODKOP_DOWN | DNS_CHAIN_DOWN | DNSMASQ_DOWN | DNSMASQ_BROKEN)
		S_OK_N=0 S_FAIL_N=0
		S_PK_FAIL_N=$((S_PK_FAIL_N + 1))
		[ "$S_PK_FAIL_N" -ge "$C_PODKOP_FAIL_THRESHOLD" ] && try_podkop_restart
		;;
	esac
}

try_podkop_restart() {
	_w=$(restart_wait)
	if [ "$_w" -gt 0 ]; then
		if [ "$S_NOTE" != budget ]; then
			notify "Сбой ($D_CLASS) не устраняется: лимит перезапусков исчерпан, следующая попытка через $((_w / 60 + 1)) мин."
		fi
		note_once budget warning "router service unhealthy ($D_CLASS), restart budget exhausted; next allowed in ${_w}s"
		return
	fi
	record_restart
	if [ "$D_CLASS" = DNSMASQ_DOWN ] || [ "$D_CLASS" = DNSMASQ_BROKEN ] ||
		{ [ "$D_CLASS" = DNS_CHAIN_DOWN ] && [ "$S_DNS_ESC" = 1 ]; }; then
		# dnsmasq is dead or not answering, or a Podkop reload did not bring local DNS back.
		log warning "router DNS unhealthy ($D_CLASS) for $S_PK_FAIL_N checks; restarting dnsmasq"
		notify "DNS роутера не отвечал (у устройств «нет интернета»). Перезапустил dnsmasq."
		S_PK_FAIL_N=0 S_NOTE='' S_DNS_ESC=0
		save_state
		"$WD_DNSMASQ_INIT" restart >/dev/null 2>&1 8>&- 9>&- || log err "dnsmasq restart returned an error"
	else
		log warning "Podkop unhealthy ($D_CLASS) for $S_PK_FAIL_N checks; reloading Podkop"
		notify "Podkop работал со сбоем ($D_CLASS). Перезапустил Podkop."
		S_PK_FAIL_N=0 S_NOTE=''
		[ "$D_CLASS" = DNS_CHAIN_DOWN ] && S_DNS_ESC=1
		save_state
		podkop_reload || log err "Podkop reload returned an error"
	fi
	DELAY=$C_SETTLE_TIME
}

# --------------------------------------------------------------- recovery ---

start_recovery() {
	if ! podkop_mode_managed; then
		note_once unmanaged warning "active node down, but podkop.$C_SEC is not connection_type=proxy + proxy_config_type=url; not switching"
		return
	fi
	_cur=$(current_proxy)
	log warning "active node id=$(node_id "$_cur") failed $S_FAIL_N consecutive checks; starting recovery"
	_now=$(now_s)
	S_REC_STARTED=$_now S_CYCLE=1 S_APPLIES=0 S_FAILED_IDS='' S_OK_N=0 S_LAST_QCHECK=$_now S_NOTE=''
	rm -f "$CAND_FILE" "$ROLLBACK_FILE"
	if [ "$S_SELF_AT" = 0 ] || [ $((_now - S_SELF_AT)) -ge 3600 ]; then
		S_PHASE=self
		set_state SELFTEST
	else
		begin_search
	fi
	DELAY=1
}

# Try the last-known-good node first, then the subscription.
begin_search() {
	_cur=$(current_proxy)
	_lkg=$(lkg_get)
	if [ -n "$_lkg" ] && ! same_node "$_lkg" "$_cur"; then
		printf '%s\n' "$_lkg" | write_atomic "$CAND_FILE"
		S_PHASE=lkg S_CAND_IDX=1
		set_state TEST
	else
		S_PHASE=initial
		set_state FETCH
	fi
}

# The active node may be fine with only Podkop's sing-box stuck (for example
# after a WAN flap). Test it in isolation; if it works, reload Podkop instead
# of switching nodes. At most once per hour, so a broken Podkop cannot loop.
st_selftest() {
	recovery_guard || return
	_cur=$(current_proxy)
	S_SELF_AT=$(now_s)
	DELAY=1
	_mem=$(mem_available_kb)
	if [ -z "$_cur" ] || [ "$_mem" -lt "$C_MIN_MEM_AVAILABLE_KB" ]; then
		begin_search
		return
	fi
	exec 8>"$WD_LOCK_FILE.test"
	if ! flock -n 8; then
		exec 8>&-
		DELAY=$C_CHECK_INTERVAL
		return
	fi
	if ! test_candidate "$_cur"; then
		exec 8>&-
		log info "active node id=$(node_id "$_cur") also fails in isolation ($T_REASON); looking for another node"
		begin_search
		return
	fi
	exec 8>&-
	if [ "$(restart_wait)" -gt 0 ]; then
		begin_search
		return
	fi
	log warning "active node id=$(node_id "$_cur") works in isolation; reloading Podkop instead of switching"
	notify "VPN не работал, хотя узел исправен. Перезапустил Podkop."
	record_restart
	end_recovery
	S_LAST_CLASS=''
	save_state
	podkop_reload || log err "Podkop reload returned an error"
	DELAY=$C_SETTLE_TIME
}

end_recovery() {
	rm -f "$CAND_FILE" "$ROLLBACK_FILE"
	S_PHASE='' S_CAND_IDX=0 S_APPLIES=0 S_FAILED_IDS='' S_FAIL_N=0 S_VERIFY_N=0 S_NOTE='' S_APPLIED_ID=''
	S_NO_NODE_AT=0
	set_state MONITOR
}

# Runs at most once per check_interval in the waiting/fetching states:
# pauses on WAN loss, stops if the user stopped Podkop or the node came back.
recovery_guard() {
	_now=$(now_s)
	[ $((_now - S_LAST_QCHECK)) -lt "$C_CHECK_INTERVAL" ] && return 0
	S_LAST_QCHECK=$_now
	if ! podkop_intent_on; then
		log notice "Podkop was stopped or disabled by the user; recovery cancelled"
		end_recovery
		DELAY=$C_CHECK_INTERVAL
		return 1
	fi
	if ! wan_ok; then
		note_once wan warning "recovery paused: WAN/internet unreachable"
		DELAY=$C_CHECK_INTERVAL
		return 1
	fi
	[ "$S_NOTE" = wan ] && { log notice "WAN reachable again; recovery resumed"; S_NOTE=''; }
	_dl=0
	dns_ok 127.0.0.1 && _dl=1
	if [ "$(tunnel_state "$_dl")" = ok ]; then
		S_OK_N=$((S_OK_N + 1))
		if [ "$S_OK_N" -ge "$C_TUNNEL_OK_THRESHOLD" ]; then
			log notice "active node is working again; recovery cancelled"
			end_recovery
			S_LAST_CLASS=''
			DELAY=$C_CHECK_INTERVAL
			return 1
		fi
	else
		S_OK_N=0
	fi
	return 0
}

# Transient API error: schedule a retry with exponential backoff (honouring
# Retry-After). Returns 1 when retries are exhausted.
api_retry() { # what
	# A failure caused by a WAN outage is not the API's fault: do not spend a retry.
	if ! wan_ok; then
		note_once wan warning "recovery paused: WAN/internet unreachable"
		DELAY=$C_CHECK_INTERVAL
		return 0
	fi
	S_ATTEMPT=$((S_ATTEMPT + 1))
	if [ "$S_ATTEMPT" -lt "$C_API_RETRIES" ]; then
		_d=$((C_API_BACKOFF << (S_ATTEMPT - 1)))
		[ -n "$API_RETRY_AFTER" ] && [ "$API_RETRY_AFTER" -gt "$_d" ] && _d=$API_RETRY_AFTER
		[ "$_d" -gt "$C_REFRESH_INTERVAL" ] && _d=$C_REFRESH_INTERVAL
		log warning "$1 failed ($(api_err_desc)); retry $S_ATTEMPT/$((C_API_RETRIES - 1)) in ${_d}s"
		DELAY=$_d
		return 0
	fi
	log warning "$1 failed ($(api_err_desc)); giving up on this step"
	S_ATTEMPT=0
	return 1
}

# No working node in the current phase: move along the recovery sequence.
advance_phase() {
	case "$S_PHASE" in
	lkg)
		S_PHASE=initial
		set_state FETCH
		;;
	initial) set_state SCAN ;;
	scan) set_state REFRESH ;;
	*)
		S_PHASE=refresh
		set_state REFRESH_WAIT
		_due=$((${S_LAST_REFRESH_AT:-0} + C_REFRESH_INTERVAL - $(now_s)))
		[ "$_due" -lt 0 ] && _due=0
		log warning "no working node found (cycle $S_CYCLE); next cache refresh in ${_due}s"
		# Once when it starts, then at most hourly.
		if [ "$S_NO_NODE_AT" = 0 ] || [ $(($(now_s) - S_NO_NODE_AT)) -ge 3600 ]; then
			S_NO_NODE_AT=$(now_s)
			notify "VPN не работает: рабочих узлов пока нет (цикл $S_CYCLE). Продолжаю искать каждые 10 мин; обычный интернет работает."
		fi
		;;
	esac
	DELAY=1
}

st_fetch() {
	recovery_guard || return
	if ! api_req GET "/vless/sub?$C_SUB_QUERY"; then
		if api_transient && api_retry "subscription fetch"; then return; fi
		api_transient || log warning "subscription fetch failed ($(api_err_desc))"
		rm -f "$API_BODY"
		advance_phase
		return
	fi
	_r=$(parse_subscription "$API_BODY" "$CAND_FILE")
	rm -f "$API_BODY"
	_cur=$(current_proxy)
	_lkg=$(lkg_get)
	# Always give the last-known-good node another chance at the end of the list.
	if [ -n "$_lkg" ] && ! same_node "$_lkg" "$_cur" && ! grep -qxF -- "${_lkg%%#*}" "$CAND_FILE"; then
		printf '%s\n' "$_lkg" >>"$CAND_FILE"
	fi
	_total=$(wc -l <"$CAND_FILE" | tr -d ' ')
	log info "subscription: ${_r% *} usable, ${_r#* } rejected, $_total to test (phase $S_PHASE)"
	if [ "$_total" -eq 0 ]; then
		advance_phase
		return
	fi
	S_CAND_IDX=1
	set_state TEST
	DELAY=1
}

st_test() {
	recovery_guard || return
	_total=0
	[ -f "$CAND_FILE" ] && _total=$(wc -l <"$CAND_FILE" | tr -d ' ')
	_cur=$(current_proxy)
	_u=''
	while [ "$S_CAND_IDX" -le "$_total" ]; do
		_u=$(sed -n "${S_CAND_IDX}p" "$CAND_FILE")
		_id=$(node_id "$_u")
		if [ -n "$_u" ] && ! same_node "$_u" "$_cur" && ! in_list "$_id" "$S_FAILED_IDS"; then
			break
		fi
		S_CAND_IDX=$((S_CAND_IDX + 1))
	done
	if [ "$S_CAND_IDX" -gt "$_total" ]; then
		rm -f "$CAND_FILE"
		advance_phase
		return
	fi
	if [ "$S_APPLIES" -ge "$C_MAX_APPLIES_PER_ROUND" ]; then
		log warning "switch limit for this cycle reached ($S_APPLIES)"
		rm -f "$CAND_FILE"
		advance_phase
		return
	fi
	_mem=$(mem_available_kb)
	if [ "$_mem" -lt "$C_MIN_MEM_AVAILABLE_KB" ]; then
		note_once lowmem warning "low memory (${_mem} kB available); candidate tests postponed"
		DELAY=$C_CHECK_INTERVAL
		return
	fi
	# Serialise with `podkop-watchdog test-candidates` (one sing-box test at a time).
	exec 8>"$WD_LOCK_FILE.test"
	if ! flock -n 8; then
		exec 8>&-
		DELAY=$C_CHECK_INTERVAL
		return
	fi
	if test_candidate "$_u"; then
		exec 8>&-
		log notice "candidate id=$_id passed isolated test"
		set_state APPLY
	else
		exec 8>&-
		log info "candidate id=$_id failed isolated test ($T_REASON)"
		S_CAND_IDX=$((S_CAND_IDX + 1))
	fi
	DELAY=1
}

st_apply() {
	if [ "$S_STATE" = APPLYING ]; then
		# Interrupted mid-switch (crash/restart): find out what is live now.
		log warning "resuming after an interrupted switch; verifying"
		S_VERIFY_N=0
		set_state VERIFY
		DELAY=$C_SETTLE_TIME
		return
	fi
	_u=$(sed -n "${S_CAND_IDX}p" "$CAND_FILE" 2>/dev/null)
	if [ -z "$_u" ]; then
		log err "selected candidate is missing; continuing with the next one"
		set_state TEST
		DELAY=1
		return
	fi
	if ! podkop_mode_managed; then
		log warning "podkop.$C_SEC is no longer in url mode; recovery cancelled"
		end_recovery
		return
	fi
	if podkop_has_staged_changes; then
		note_once staged warning "podkop has uncommitted changes (LuCI edit in progress?); switch postponed"
		DELAY=$C_CHECK_INTERVAL
		return
	fi
	_w=$(restart_wait)
	if [ "$_w" -gt 0 ]; then
		note_once budget warning "switch postponed by restart budget for ${_w}s"
		DELAY=$_w
		return
	fi
	S_NOTE=''
	# Keep the pre-recovery configuration for rollback (first switch only).
	[ -s "$ROLLBACK_FILE" ] || current_proxy | write_atomic "$ROLLBACK_FILE"
	_id=$(node_id "$_u")
	S_APPLIED_ID=$_id
	S_STATE=APPLYING
	S_APPLIES=$((S_APPLIES + 1))
	record_restart
	save_state # persisted before the side effect
	log notice "switching Podkop to node id=$_id"
	podkop_set_proxy "$_u"
	_rc=$?
	if [ "$_rc" -eq 1 ]; then
		log err "uci update failed; configuration unchanged"
		S_FAILED_IDS="$S_FAILED_IDS $_id"
		S_CAND_IDX=$((S_CAND_IDX + 1))
		set_state TEST
		DELAY=1
		return
	fi
	if [ "$_rc" -eq 2 ]; then
		log err "Podkop reload failed after switch; rolling back"
		set_state ROLLBACK
		DELAY=1
		return
	fi
	S_VERIFY_N=0
	set_state VERIFY
	DELAY=$C_SETTLE_TIME
}

st_verify() {
	if ! wan_ok; then
		note_once wan warning "verification paused: WAN/internet unreachable"
		DELAY=$C_CHECK_INTERVAL
		return
	fi
	[ "$S_NOTE" = wan ] && S_NOTE=''
	_n=$(node_check)
	_ok=0
	# A node switch does not touch nft/DNS, so the real request through Podkop's
	# own sing-box decides. The full path is only a fallback without the Clash API.
	if [ "$_n" = ok ]; then
		_ok=1
	elif [ "$_n" = unknown ]; then
		full_path_ok && _ok=1
	fi
	if [ "$_ok" = 1 ]; then
		lkg_set "$(current_proxy)"
		log notice "recovery complete: node id=$S_APPLIED_ID verified through Podkop ($(($(now_s) - S_REC_STARTED))s, $S_APPLIES switch(es))"
		notify "VPN восстановлен: новый узел id=$S_APPLIED_ID, за $((($(now_s) - S_REC_STARTED) / 60)) мин."
		end_recovery
		S_OK_N=$C_TUNNEL_OK_THRESHOLD
		S_LAST_CLASS=HEALTHY
		DELAY=$C_CHECK_INTERVAL
		return
	fi
	S_VERIFY_N=$((S_VERIFY_N + 1))
	if [ "$S_VERIFY_N" -ge "$C_VERIFY_ATTEMPTS" ]; then
		log warning "node id=$S_APPLIED_ID failed verification after switch (node=$_n); rolling back"
		set_state ROLLBACK
		DELAY=1
	else
		DELAY=$C_VERIFY_INTERVAL
	fi
}

st_rollback() {
	if [ ! -f "$ROLLBACK_FILE" ]; then
		log err "no rollback copy available; keeping current configuration"
	else
		podkop_has_staged_changes && log warning "rollback will also commit pending podkop changes"
		record_restart # counted, but never blocked by the budget
		save_state
		if podkop_set_proxy "$(cat "$ROLLBACK_FILE")"; then
			log notice "rolled back to the previous configuration"
		else
			log err "rollback failed; retrying in ${C_RESTART_MIN_INTERVAL}s"
			DELAY=$C_RESTART_MIN_INTERVAL
			return
		fi
	fi
	S_FAILED_IDS="${S_FAILED_IDS:+$S_FAILED_IDS }$S_APPLIED_ID"
	S_CAND_IDX=$((S_CAND_IDX + 1))
	set_state TEST
	DELAY=$C_SETTLE_TIME
}

st_scan() {
	recovery_guard || return
	S_PHASE=scan
	if api_req POST /scan; then
		_o=$(json_field outcome)
		log info "scan requested: outcome=${_o:-?}"
		case "$_o" in
		started | joined)
			S_DEADLINE=$(($(now_s) + C_SCAN_WAIT_MAX))
			set_state SCAN_WAIT
			DELAY=$C_SCAN_POLL_INTERVAL
			return
			;;
		esac
	elif api_transient && api_retry "scan request"; then
		return
	else
		log warning "scan request failed ($(api_err_desc)); fetching subscription anyway"
	fi
	set_state FETCH
	DELAY=1
}

st_scan_wait() {
	recovery_guard || return
	if api_req GET /scan/status && [ "$(json_field is_scanning)" = false ]; then
		log info "scan finished"
		set_state FETCH
		DELAY=1
		return
	fi
	if [ "$(now_s)" -ge "$S_DEADLINE" ]; then
		log warning "scan did not finish within ${C_SCAN_WAIT_MAX}s; fetching subscription anyway"
		set_state FETCH
		DELAY=1
		return
	fi
	DELAY=$C_SCAN_POLL_INTERVAL
}

st_refresh() {
	recovery_guard || return
	if [ "$S_ATTEMPT" -eq 0 ]; then
		# A new refresh cycle: the 10-minute spacing is measured from here.
		S_LAST_REFRESH_AT=$(now_s)
		S_CYCLE=$((S_CYCLE + 1))
		S_APPLIES=0 S_FAILED_IDS=''
	fi
	S_PHASE=refresh
	if api_req POST /cache/refresh; then
		_o=$(json_field outcome)
		log info "cache refresh requested: outcome=${_o:-?} (cycle $S_CYCLE)"
		case "$_o" in
		started | joined)
			S_DEADLINE=$(($(now_s) + C_SCAN_WAIT_MAX))
			set_state SCAN_WAIT
			DELAY=$C_SCAN_POLL_INTERVAL
			return
			;;
		esac
		set_state FETCH
		DELAY=1
		return
	fi
	if [ "$API_CURL_RC" -eq 0 ] && [ "$API_CODE" = 429 ]; then
		# Server-side cooldown: someone refreshed recently; use those results.
		log info "cache was refreshed recently (retry-after=${API_RETRY_AFTER:-?}); using current results"
		S_DEADLINE=$(($(now_s) + C_SCAN_WAIT_MAX))
		set_state SCAN_WAIT
		DELAY=1
		return
	fi
	if api_transient && api_retry "cache refresh"; then return; fi
	log warning "cache refresh failed ($(api_err_desc))"
	advance_phase
}

st_refresh_wait() {
	recovery_guard || return
	_due=$((${S_LAST_REFRESH_AT:-0} + C_REFRESH_INTERVAL))
	_now=$(now_s)
	if [ "$_now" -ge "$_due" ]; then
		set_state REFRESH
		DELAY=1
		return
	fi
	DELAY=$((_due - _now))
	[ "$DELAY" -gt "$C_CHECK_INTERVAL" ] && DELAY=$C_CHECK_INTERVAL
}

# ------------------------------------------------------------------ tick ---

# ------------------------------------------------------------ WAN repair ---

wnote() { # key level message   -- WAN notes, independent of S_NOTE
	[ "$S_WAN_NOTE" = "$1" ] && return 0
	log "$2" "$3"
	S_WAN_NOTE=$1
}

wan_restart() {
	ubus call "network.interface.$C_WAN_INTERFACE" down >/dev/null 2>&1 8>&- 9>&-
	ubus call "network.interface.$C_WAN_INTERFACE" up >/dev/null 2>&1 8>&- 9>&- ||
		ubus call "network.interface.$C_WAN_INTERFACE" up >/dev/null 2>&1 8>&- 9>&-
}

# Restarts the WAN interface when it stays without internet (for example a
# PPPoE session that does not come up after boot). Runs on its own timer,
# independent of Podkop and of the recovery states. Returns 1 when this tick
# was spent on a restart.
wan_watch() {
	[ "$C_WAN_REPAIR" = 1 ] || return 0
	_wnow=$(now_s)
	[ "$S_WAN_AT" -gt "$_wnow" ] && return 0
	S_WAN_AT=$((_wnow + C_CHECK_INTERVAL))
	if ! wan_status; then
		wnote noif err "WAN interface '$C_WAN_INTERFACE' not found; WAN repair inactive"
		return 0
	fi
	W_INET=0
	[ "$W_LINK" = 1 ] && internet_up && W_INET=1
	W_CHECKED=1
	_delta=0
	if _rx=$(wan_rx_bytes "$W_L3"); then
		if [ -n "$S_WAN_RX" ] && [ "$_rx" -ge "$S_WAN_RX" ]; then _delta=$((_rx - S_WAN_RX)); fi
		S_WAN_RX=$_rx
	else
		S_WAN_RX=''
	fi

	if [ "$W_INET" = 1 ]; then
		if [ "$S_WAN_FIXES" -gt 0 ]; then
			log notice "WAN is up again after $S_WAN_FIXES interface restart(s)"
			notify "Интернет восстановлен после $S_WAN_FIXES перезапуск(ов) WAN, простой ~$(((_wnow - S_WAN_DOWN_AT) / 60)) мин."
		elif [ "$S_WAN_SUSPECT" = 1 ]; then
			notify "Проверки роутера снова проходят."
		fi
		S_WAN_FAIL_N=0 S_WAN_FIXES=0 S_WAN_REPAIR_AT=0 S_WAN_NOTE='' S_WAN_TRAFFIC=0 S_WAN_SUSPECT=0
		S_WAN_DOWN_AT=0
		return 0
	fi
	[ "$S_WAN_DOWN_AT" = 0 ] && S_WAN_DOWN_AT=$_wnow
	if [ "$W_AUTO" = 0 ] && [ "$S_WAN_FIXES" = 0 ]; then
		wnote manual notice "WAN interface '$C_WAN_INTERFACE' was stopped manually; not restarting it"
		S_WAN_FAIL_N=0
		return 0
	fi
	if [ "$_delta" -ge "$C_WAN_RX_ACTIVE_BYTES" ]; then
		# The router's own probes fail but traffic flows: do not cut working clients off.
		S_WAN_TRAFFIC=1 S_WAN_FAIL_N=0
		if [ "$S_WAN_FIXES" -gt 0 ] && [ "$S_WAN_SUSPECT" = 0 ]; then
			# A restart did not make the probes pass, yet LAN traffic flows:
			# the WAN works and the problem is on the router's side.
			S_WAN_SUSPECT=1
			log warning "LAN traffic flows but the router's own checks still fail after a WAN restart; WAN restarts held back"
			notify "Устройства в сети пользуются интернетом, но проверки самого роутера не проходят. WAN перезапущу, только если трафик полностью пропадёт на 15 мин."
		else
			wnote traffic warning "connectivity checks fail but WAN is carrying traffic; not restarting it"
		fi
		return 0
	fi
	S_WAN_FAIL_N=$((S_WAN_FAIL_N + 1))
	# The more evidence that the WAN works, the longer it must stay silent first.
	_thr=$C_WAN_FAIL_THRESHOLD
	[ "$S_WAN_TRAFFIC" = 1 ] && _thr=$((C_WAN_FAIL_THRESHOLD * 3))
	[ "$S_WAN_SUSPECT" = 1 ] && _thr=$((C_WAN_FAIL_THRESHOLD * 10))
	[ "$S_WAN_FAIL_N" -lt "$_thr" ] && return 0
	if [ "$S_WAN_REPAIR_AT" -gt "$_wnow" ]; then
		wnote wait info "WAN still down; next interface restart in $((S_WAN_REPAIR_AT - _wnow))s"
		return 0
	fi
	S_WAN_FIXES=$((S_WAN_FIXES + 1))
	_b=$C_WAN_REPAIR_MAX_INTERVAL
	[ "$S_WAN_FIXES" -le 12 ] && _b=$((C_WAN_REPAIR_BACKOFF << (S_WAN_FIXES - 1)))
	[ "$_b" -gt "$C_WAN_REPAIR_MAX_INTERVAL" ] && _b=$C_WAN_REPAIR_MAX_INTERVAL
	log warning "WAN without internet for $S_WAN_FAIL_N checks (link=$W_LINK); restarting interface '$C_WAN_INTERFACE' (attempt $S_WAN_FIXES)"
	case "$S_WAN_FIXES" in
	1) notify "Нет интернета ~$(((_wnow - S_WAN_DOWN_AT) / 60)) мин. Перезапускаю WAN." ;;
	3) notify "Перезапуски WAN не помогают (3 попытки). Вероятно, проблема у провайдера или с кабелем. Продолжаю пробовать каждые до 30 мин." ;;
	esac
	S_WAN_REPAIR_AT=$((_wnow + _b))
	S_WAN_FAIL_N=0 S_WAN_NOTE='' S_WAN_RX=''
	S_WAN_AT=$((_wnow + C_WAN_SETTLE))
	save_state # persist first: a crash here must not cause a restart burst
	wan_restart || log err "WAN interface restart returned an error"
	return 1
}

# ---------------------------------------------------------- Wi-Fi repair ---

# Per-radio state: "<radio> <fail_n> <stall_n> <tx> <fixes> <repair_at> <note>"
WIFI_STATE="$WD_STATE_DIR/wifi"

wifi_restart() { # radio
	_wj="{\"device\":\"$1\"}"
	ubus call network.wireless down "$_wj" >/dev/null 2>&1 8>&- 9>&-
	ubus call network.wireless up "$_wj" >/dev/null 2>&1 8>&- 9>&- ||
		ubus call network.wireless up "$_wj" >/dev/null 2>&1 8>&- 9>&-
}

# Restarts a single radio that is enabled in config but down, lost its
# hostapd/wpa_supplicant, or stopped transmitting while clients are connected.
# Radios disabled in config or stopped with `wifi down` are left alone.
wifi_watch() {
	[ "$C_WIFI_REPAIR" = 1 ] || return 0
	_inow=$(now_s)
	[ "$S_WIFI_AT" -gt "$_inow" ] && return 0
	S_WIFI_AT=$((_inow + 2 * C_CHECK_INTERVAL))
	_radios=$(wifi_radios) || return 0
	[ -n "$_radios" ] || return 0
	_inew="$WIFI_STATE.new"
	: >"$_inew"
	printf '%s\n' "$_radios" | while read -r _r _up _pend _auto _ifs; do
		printf '%s' "$_r" | grep -Eq '^[A-Za-z0-9_]+$' || continue
		_fail=0 _stall=0 _tx0='' _fix=0 _rat=0 _note=-
		if [ -f "$WIFI_STATE" ]; then
			# shellcheck disable=SC2034 # _x is the radio name column
			read -r _x _fail _stall _tx0 _fix _rat _note <<EOF2
$(grep "^$_r " "$WIFI_STATE")
EOF2
		fi
		for _v in _fail _stall _fix _rat; do eval "is_uint \"\$$_v\" || $_v=0"; done
		_why=''
		if [ "$_auto" = false ] && [ "$_fix" = 0 ]; then
			[ "$_note" = manual ] || log notice "Wi-Fi $_r was stopped manually; not restarting it"
			echo "$_r 0 0 - 0 0 manual" >>"$_inew"
			continue
		fi
		_tx=0 _cl=0
		if [ "$_up" != true ]; then
			[ "$_pend" = true ] || _why=down
		elif [ "$_ifs" != - ]; then
			for _if in $(echo "$_ifs" | tr ',' ' '); do
				wifi_daemon_ok "$_if" || _why=nodaemon
				_tx=$((_tx + $(wifi_tx_packets "$_if")))
				_cl=$((_cl + $(wifi_clients "$_if")))
			done
		fi
		if [ -z "$_why" ] && [ "$_up" = true ] && [ "$_cl" -gt 0 ] && [ "$_tx0" = "$_tx" ]; then
			_stall=$((_stall + 1))
			[ "$_stall" -ge "$C_WIFI_STALL_CHECKS" ] && _why=stalled
		else
			_stall=0
		fi
		if [ -z "$_why" ]; then
			if [ "$_fix" -gt 0 ]; then
				log notice "Wi-Fi $_r works again after $_fix restart(s)"
				notify "Wi-Fi ($_r) снова работает после $_fix перезапуск(ов)."
			fi
			echo "$_r 0 $_stall $_tx 0 0 -" >>"$_inew"
			continue
		fi
		_fail=$((_fail + 1))
		if { [ "$_why" != stalled ] && [ "$_fail" -lt 3 ]; } || [ "$_rat" -gt "$_inow" ]; then
			echo "$_r $_fail $_stall $_tx $_fix $_rat $_why" >>"$_inew"
			continue
		fi
		_fix=$((_fix + 1))
		_b=3600
		[ "$_fix" -le 4 ] && _b=$((300 << (_fix - 1)))
		[ "$_b" -gt 3600 ] && _b=3600
		log warning "Wi-Fi $_r unhealthy ($_why); restarting it (attempt $_fix)"
		case "$_fix" in
		1) notify "Wi-Fi ($_r) не работает ($_why). Перезапускаю." ;;
		3) notify "Перезапуски Wi-Fi ($_r) не помогают (3 попытки). Может понадобиться перезагрузка роутера." ;;
		esac
		echo "$_r 0 0 - $_fix $((_inow + _b)) restarted" >>"$_inew"
		wifi_restart "$_r" || log err "Wi-Fi $_r restart returned an error"
	done
	mv -f "$_inew" "$WIFI_STATE"
	return 0
}

tick() {
	load_state
	_tnow=$(now_s)
	DELAY=$C_CHECK_INTERVAL
	if [ "$S_FRESH" = 1 ] && [ "$_tnow" -lt "$C_BOOT_GRACE" ]; then
		S_NEXT_AT=$C_BOOT_GRACE S_DUE_AT=$C_BOOT_GRACE
		DELAY=$((C_BOOT_GRACE - _tnow))
		log info "boot grace: first check in ${DELAY}s"
		notify "Роутер включился (перезагрузка или отключение питания). Проверю всё через $DELAY с."
		save_state
		return
	fi
	if [ "$S_NEXT_AT" -gt "$_tnow" ]; then
		# Persisted schedule: a restart or crash loop cannot cause request bursts.
		DELAY=$((S_NEXT_AT - _tnow))
		return
	fi
	W_CHECKED=0
	if wan_watch; then
		if [ "$S_DUE_AT" -le "$_tnow" ]; then
			case "$S_STATE" in
			MONITOR) st_monitor ;;
			SELFTEST) st_selftest ;;
			FETCH) st_fetch ;;
			TEST) st_test ;;
			APPLY | APPLYING) st_apply ;;
			VERIFY) st_verify ;;
			ROLLBACK) st_rollback ;;
			SCAN) st_scan ;;
			SCAN_WAIT) st_scan_wait ;;
			REFRESH) st_refresh ;;
			REFRESH_WAIT) st_refresh_wait ;;
			*)
				log err "unknown state '$S_STATE'; resetting to MONITOR"
				end_recovery
				;;
			esac
			is_uint "$DELAY" || DELAY=$C_CHECK_INTERVAL
			[ "$DELAY" -lt 1 ] && DELAY=1
			S_DUE_AT=$(($(now_s) + DELAY))
		fi
	elif [ "$S_DUE_AT" -lt "$S_WAN_AT" ]; then
		S_DUE_AT=$S_WAN_AT # let the WAN settle before the next recovery step
	fi
	wifi_watch
	notify_flush
	# Wake for whichever comes first: the next state step or the next WAN check.
	_tnow=$(now_s)
	_wake=$S_DUE_AT
	[ "$C_WAN_REPAIR" = 1 ] && [ "$S_WAN_AT" -lt "$_wake" ] && _wake=$S_WAN_AT
	[ "$C_WIFI_REPAIR" = 1 ] && [ "$S_WIFI_AT" -lt "$_wake" ] && _wake=$S_WIFI_AT
	[ "$_wake" -le "$_tnow" ] && _wake=$((_tnow + 1))
	S_NEXT_AT=$_wake
	DELAY=$((_wake - _tnow))
	save_state
}
