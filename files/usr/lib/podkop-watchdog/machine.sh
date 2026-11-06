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
		S_FAIL_N=0 S_PK_FAIL_N=0 S_DNS_ESC=0 S_ESC_N=0
		S_OK_N=$((S_OK_N + 1))
		if [ "$D_CLASS" = TUNNEL_UNKNOWN ]; then
			# Clash silent for several checks in a row (not a one-off blip): tell the
			# owner, at most every 6 hours.
			S_UNK_N=$((S_UNK_N + 1))
			_un=$(now_s)
			if [ "$S_UNK_N" -ge "$C_TUNNEL_FAIL_THRESHOLD" ] && { [ "$S_UNK_AT" = 0 ] || [ $((_un - S_UNK_AT)) -ge 21600 ]; }; then
				S_UNK_AT=$_un
				notify "Не могу проверить VPN: Clash API Podkop недоступен. Автопереключение узлов приостановлено, ремонт роутера продолжается."
			fi
		else
			S_UNK_N=0
		fi
		if [ "$D_CLASS" = HEALTHY ] && [ "$S_OK_N" -ge "$C_TUNNEL_OK_THRESHOLD" ] && podkop_mode_managed; then
			_cur=$(current_proxy)
			[ -n "$_cur" ] && lkg_set "$_cur"
		fi
		;;
	PODKOP_OFF | WAN_DOWN | DNS_UPSTREAM_DOWN | PATH_DOWN)
		S_ESC_N=0 S_UNK_N=0
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

# Escalation shared by every "restart something" action: after 3 restarts that
# did not bring the router back, tell the owner once and slow down (a broken user
# config cannot be fixed by a reload). Returns 1 while held back.
esc_gate() { # note-function
	_now=$(now_s)
	if [ "$S_ESC_N" -ge 3 ]; then
		_pause=3600
		[ "$S_ESC_N" -le 8 ] && _pause=$((C_RESTART_MIN_INTERVAL << (S_ESC_N - 2)))
		[ "$_pause" -gt 3600 ] && _pause=3600
		if [ $((_now - S_ESC_AT)) -lt "$_pause" ]; then
			"$1" escalated warning "router service still unhealthy after $S_ESC_N restarts; retrying less often"
			return 1
		fi
	fi
	S_ESC_N=$((S_ESC_N + 1))
	S_ESC_AT=$_now
	[ "$S_ESC_N" = 3 ] && notify "Сбой не устраняется перезапусками (3 попытки). Нужна проверка роутера вручную; дальше пробую реже."
	return 0
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
	_tgt=podkop
	if [ "$D_CLASS" = DNSMASQ_DOWN ] || [ "$D_CLASS" = DNSMASQ_BROKEN ] ||
		{ [ "$D_CLASS" = DNS_CHAIN_DOWN ] && [ "$S_DNS_ESC" = 1 ]; }; then
		# dnsmasq is dead or not answering, or a Podkop reload did not bring local DNS back.
		_tgt=dnsmasq
		if ! dnsmasq_managed; then
			# Disabled on purpose (AdGuard Home, smartdns...): never start it.
			note_once dnsoff warning "router DNS unhealthy ($D_CLASS) but dnsmasq is disabled by the user; not touching it"
			S_PK_FAIL_N=0 S_DNS_ESC=0
			return
		fi
	fi
	if svc_busy "$_tgt"; then
		# An earlier action is still hanging: do not count a restart that never happened.
		note_once busy warning "$_tgt action is still running; not starting another"
		return
	fi
	esc_gate note_once || return
	record_restart
	if [ "$_tgt" = dnsmasq ]; then
		log warning "router DNS unhealthy ($D_CLASS) for $S_PK_FAIL_N checks; restarting dnsmasq"
		[ "$S_ESC_N" -le 2 ] && notify "DNS роутера не отвечал (у устройств «нет интернета»). Перезапустил dnsmasq."
		S_PK_FAIL_N=0 S_NOTE='' S_DNS_ESC=0
		save_state
		dnsmasq_restart || log err "dnsmasq restart returned an error"
	else
		log warning "Podkop unhealthy ($D_CLASS) for $S_PK_FAIL_N checks; reloading Podkop"
		[ "$S_ESC_N" -le 2 ] && notify "Podkop работал со сбоем ($D_CLASS). Перезапустил Podkop."
		S_PK_FAIL_N=0 S_NOTE=''
		[ "$D_CLASS" = DNS_CHAIN_DOWN ] && S_DNS_ESC=1
		save_state
		podkop_reload || log err "Podkop reload returned an error"
	fi
	DELAY=$C_SETTLE_TIME
}

dnote() { # key level message   -- dns_watch notes, independent of S_NOTE
	[ "$S_DNS_NOTE" = "$1" ] && return 0
	log "$2" "$3"
	S_DNS_NOTE=$1
}

dnsmasq_restart() {
	svc_run dnsmasq "$C_SERVICE_TIMEOUT" "$WD_DNSMASQ_INIT" restart
	_drc=$?
	svc_hung dnsmasq "$_drc"
	return "$_drc"
}

# The router's DNS must be repaired in every state, not only in MONITOR: a node
# search can last for hours, and every LAN client depends on dnsmasq meanwhile.
# (MONITOR repairs it through diagnose; this covers the other states.)
dns_watch() {
	[ "$S_STATE" = MONITOR ] && return 0
	_dnow=$(now_s)
	[ "$S_DNS_AT" -gt "$_dnow" ] && return 0
	S_DNS_AT=$((_dnow + C_CHECK_INTERVAL))
	if [ "$(dnsmasq_state)" != 0 ]; then
		S_DNSM_FAIL_N=0 S_DNS_NOTE=''
		return 0
	fi
	S_DNSM_FAIL_N=$((S_DNSM_FAIL_N + 1))
	[ "$S_DNSM_FAIL_N" -ge "$C_PODKOP_FAIL_THRESHOLD" ] || return 0
	_dw=$(restart_wait)
	if [ "$_dw" -gt 0 ]; then
		dnote dnsbudget warning "dnsmasq is down during recovery, restart budget exhausted"
		return 0
	fi
	if svc_busy dnsmasq; then
		dnote busy warning "dnsmasq action is still running; not starting another"
		return 0
	fi
	esc_gate dnote || return 0
	record_restart
	S_DNSM_FAIL_N=0
	log warning "dnsmasq is down while Podkop recovery is running; restarting it"
	[ "$S_ESC_N" -le 2 ] && notify "DNS роутера не отвечал (у устройств «нет интернета»). Перезапустил dnsmasq."
	save_state
	dnsmasq_restart || log err "dnsmasq restart returned an error"
}

# --------------------------------------------------------------- recovery ---

start_recovery() {
	if ! podkop_mode_managed; then
		note_once unmanaged warning "active node down, but podkop.$C_SEC is not connection_type=proxy + proxy_config_type=url; not switching"
		return
	fi
	if [ "$S_COMPAT" = 0 ]; then
		note_once compat warning "active node down, but node failover is disabled (incompatible Podkop/sing-box: $S_COMPAT_WHY)"
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
	if [ "$S_PHASE" != self_ok ]; then
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
		S_PHASE=self_ok # tested once; from now on only wait for the budget
	fi
	_w=$(restart_wait)
	if [ "$_w" -gt 0 ]; then
		# The node works: wait for the restart budget rather than switch it.
		note_once budget warning "active node works in isolation; Podkop reload postponed by restart budget for ${_w}s"
		[ "$_w" -gt 300 ] && _w=300
		DELAY=$_w
		return
	fi
	if svc_busy podkop; then
		note_once busy warning "an earlier Podkop action is still running; reload postponed"
		DELAY=$C_CHECK_INTERVAL
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
	S_PHASE='' S_CAND_IDX=0 S_APPLIES=0 S_FAILED_IDS='' S_FAIL_N=0 S_VERIFY_N=0 S_NOTE='' S_APPLIED_ID='' S_RB_FAIL_N=0 S_DNSM_FAIL_N=0
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
	if [ "$(tunnel_state)" = ok ]; then
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
	if ! podkop_intent_on; then
		log notice "Podkop was stopped or disabled by the user; recovery cancelled"
		end_recovery
		DELAY=$C_CHECK_INTERVAL
		return
	fi
	if ! podkop_mode_managed; then
		log warning "podkop.$C_SEC is no longer in url mode; recovery cancelled"
		end_recovery
		return
	fi
	if svc_busy podkop; then
		note_once busy warning "an earlier Podkop action is still running; switch postponed"
		DELAY=$C_CHECK_INTERVAL
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
	if ! podkop_intent_on; then
		log notice "Podkop was stopped or disabled by the user; verification cancelled"
		end_recovery
		DELAY=$C_CHECK_INTERVAL
		return
	fi
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
	if ! podkop_intent_on; then
		log notice "Podkop was stopped or disabled by the user; rollback skipped"
		end_recovery
		DELAY=$C_CHECK_INTERVAL
		return
	fi
	if svc_busy podkop; then
		# Not a failed rollback: the earlier reload is still reading the configuration.
		note_once busy warning "an earlier Podkop action is still running; rollback waits"
		DELAY=$C_CHECK_INTERVAL
		return
	fi
	if [ ! -f "$ROLLBACK_FILE" ]; then
		log err "no rollback copy available; keeping current configuration"
	else
		podkop_has_staged_changes && log warning "rollback will also commit pending podkop changes"
		record_restart # counted, but never blocked by the budget
		save_state
		if podkop_set_proxy "$(cat "$ROLLBACK_FILE")"; then
			log notice "rolled back to the previous configuration"
			S_RB_FAIL_N=0
		else
			# Exponential pause (60, 120, ... 1800 s): a reload that keeps failing
			# must not run once a minute forever.
			S_RB_FAIL_N=$((S_RB_FAIL_N + 1))
			_d=1800
			[ "$S_RB_FAIL_N" -le 5 ] && _d=$((C_RESTART_MIN_INTERVAL << (S_RB_FAIL_N - 1)))
			[ "$_d" -gt 1800 ] && _d=1800
			log err "rollback failed (attempt $S_RB_FAIL_N); retrying in ${_d}s"
			if [ "$S_RB_FAIL_N" -ge 8 ]; then
				log err "rollback failed $S_RB_FAIL_N times; giving up and returning to monitoring"
				notify "Не удалось вернуть прежние настройки Podkop за 8 попыток. Слежу дальше в обычном режиме; нужна проверка вручную."
				end_recovery
				DELAY=$C_CHECK_INTERVAL
				return
			fi
			[ "$S_RB_FAIL_N" = 3 ] && notify "Не удаётся вернуть прежние настройки Podkop (3 попытки). Нужно проверить роутер вручную; продолжаю пробовать с паузой."
			DELAY=$_d
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
	ubus_t call "network.interface.$WAN_IF" down >/dev/null 2>&1 8>&- 9>&-
	ubus_t call "network.interface.$WAN_IF" up >/dev/null 2>&1 8>&- 9>&- ||
		ubus_t call "network.interface.$WAN_IF" up >/dev/null 2>&1 8>&- 9>&-
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
	wan_resolve
	if ! wan_status; then
		wnote noif err "WAN interface '${WAN_IF:-auto}' not found; WAN repair inactive (connectivity is judged by probes only)"
		return 0
	fi
	W_INET=0
	if [ "$W_LINK" = 1 ] || [ -z "$C_WAN_INTERFACE" ]; then
		internet_up && W_INET=1 # (auto-detected interface: the link may be the wrong one)
	fi
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
		wnote manual notice "WAN interface '$WAN_IF' was stopped manually; not restarting it"
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
	if [ -z "$C_WAN_INTERFACE" ]; then
		# The remembered interface may no longer be the one carrying traffic
		# (backup link took over, then the main one came back).
		_walt=$(wan_detect_active)
		if [ -n "$_walt" ] && [ "$_walt" != "$WAN_IF" ]; then
			log notice "WAN interface changed: $WAN_IF -> $_walt"
			S_WAN_IF=$_walt WAN_IF=$_walt S_WAN_FAIL_N=0
			return 0
		fi
	fi
	if [ "$S_WAN_REPAIR_AT" -gt "$_wnow" ]; then
		wnote wait info "WAN still down; next interface restart in $((S_WAN_REPAIR_AT - _wnow))s"
		return 0
	fi
	S_WAN_FIXES=$((S_WAN_FIXES + 1))
	_b=$C_WAN_REPAIR_MAX_INTERVAL
	[ "$S_WAN_FIXES" -le 12 ] && _b=$((C_WAN_REPAIR_BACKOFF << (S_WAN_FIXES - 1)))
	[ "$_b" -gt "$C_WAN_REPAIR_MAX_INTERVAL" ] && _b=$C_WAN_REPAIR_MAX_INTERVAL
	log warning "WAN without internet for $S_WAN_FAIL_N checks (link=$W_LINK); restarting interface '$WAN_IF' (attempt $S_WAN_FIXES)"
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
	ubus_t call network.wireless down "$_wj" >/dev/null 2>&1 8>&- 9>&-
	ubus_t call network.wireless up "$_wj" >/dev/null 2>&1 8>&- 9>&- ||
		ubus_t call network.wireless up "$_wj" >/dev/null 2>&1 8>&- 9>&-
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

# Podkop's internals are not a public contract: check hourly (and after a
# restart) that the parts the failover depends on still behave as expected. If
# not, node switching is disabled (router repair goes on) and the owner is told.
compat_watch() {
	_cn=$(now_s)
	[ "$S_COMPAT_AT" -gt 0 ] && [ $((_cn - S_COMPAT_AT)) -lt 3600 ] && [ "$_cn" -ge "$S_COMPAT_AT" ] && return 0
	S_COMPAT_AT=$_cn
	[ "$S_STATE" = MONITOR ] || return 0 # never test while a recovery owns the sing-box test slot
	_why=$(compat_probe)
	if [ -z "$_why" ]; then
		if [ "$S_COMPAT" = 0 ]; then
			log notice "Podkop compatibility restored; node failover enabled"
			notify "Совместимость с Podkop восстановлена: автопереключение узлов снова включено."
		fi
		S_COMPAT=1 S_COMPAT_WHY=''
	else
		if [ "$S_COMPAT" = 1 ] || [ "$S_COMPAT_WHY" != "$_why" ]; then
			log err "Podkop compatibility check failed ($_why); node failover disabled, router repair continues"
			notify "Podkop или sing-box изменились ($_why): автопереключение узлов отключено, ремонт роутера продолжается."
		fi
		S_COMPAT=0 S_COMPAT_WHY=$_why
	fi
}

# Once a day: proof of life for an owner who has no other way to notice that the
# watchdog itself stopped.
heartbeat() {
	[ "$C_HEARTBEAT" = 1 ] || return 0
	notify_enabled || return 0
	_hn=$(now_s)
	[ "$S_HB_AT" -gt 0 ] && [ $((_hn - S_HB_AT)) -lt 86400 ] && [ "$_hn" -ge "$S_HB_AT" ] && return 0
	_first=0
	[ "$S_HB_AT" = 0 ] && _first=1
	S_HB_AT=$_hn
	[ "$_first" = 1 ] && return 0 # the first one is due a day after the start
	notify "Ежедневная сводка: watchdog работает. Состояние: ${S_LAST_CLASS:-?}, аптайм $((_hn / 3600)) ч, свободно RAM $(($(mem_available_kb) / 1024)) МБ."
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
	W_CHECKED=0 W_TRIED=0
	wan_resolve
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
	dns_watch
	wifi_watch
	compat_watch
	heartbeat
	notify_flush
	# Wake for whichever comes first: the next state step or the next WAN check.
	_tnow=$(now_s)
	_wake=$S_DUE_AT
	[ "$C_WAN_REPAIR" = 1 ] && [ "$S_WAN_AT" -lt "$_wake" ] && _wake=$S_WAN_AT
	[ "$C_WIFI_REPAIR" = 1 ] && [ "$S_WIFI_AT" -lt "$_wake" ] && _wake=$S_WIFI_AT
	[ "$S_STATE" != MONITOR ] && [ "$S_DNS_AT" -lt "$_wake" ] && _wake=$S_DNS_AT
	[ "$_wake" -le "$_tnow" ] && _wake=$((_tnow + 1))
	S_NEXT_AT=$_wake
	DELAY=$((_wake - _tnow))
	save_state
}
