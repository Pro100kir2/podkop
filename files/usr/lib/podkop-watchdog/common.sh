# podkop-watchdog: shared helpers (config, logging, clock, state, process control).
# POSIX sh / busybox ash. Sourced by /usr/bin/podkop-watchdog.
# shellcheck shell=sh disable=SC2034 # globals are shared across sourced modules

: "${WD_PKG:=podkop-watchdog}"
: "${WD_STATE_DIR:=/tmp/podkop-watchdog}"
: "${WD_PERSIST_DIR:=/etc/podkop-watchdog}"
: "${WD_LOCK_FILE:=/var/lock/podkop-watchdog.lock}"
: "${WD_UPTIME_FILE:=/proc/uptime}"
: "${WD_MEMINFO_FILE:=/proc/meminfo}"
: "${WD_PODKOP_INIT:=/etc/init.d/podkop}"
: "${WD_PODKOP_LIB:=/usr/lib/podkop}"
: "${WD_DNSMASQ_INIT:=/etc/init.d/dnsmasq}"
: "${WD_SYS_NET:=/sys/class/net}"
: "${WD_EVENT_LOG:=$WD_PERSIST_DIR/events.log}"
: "${WD_HOSTNAME_FILE:=/proc/sys/kernel/hostname}"

STATE_FILE="$WD_STATE_DIR/state"
CAND_FILE="$WD_STATE_DIR/candidates"
ROLLBACK_FILE="$WD_STATE_DIR/rollback"
TMP_DIR="$WD_STATE_DIR/tmp"

# Mark used by Podkop's own sing-box traffic; nft mangle_output returns early for it.
PODKOP_OUTBOUND_MARK=2097152 # 0x00200000

log() { # level message...
	_lvl="$1"
	shift
	logger -t podkop-watchdog -p "daemon.$_lvl" -- "$*" 2>/dev/null || true
	case "$_lvl" in err | warning | notice) event_write "$_lvl" "$*" ;; esac
}

now_s() {
	_up=0
	read -r _up _ <"$WD_UPTIME_FILE" 2>/dev/null
	echo "${_up%%.*}"
}

is_uint() { case "$1" in '' | *[!0-9]*) return 1 ;; *) return 0 ;; esac }

# Short, non-reversible node identifier for logs (never log URLs/UUIDs/hosts).
# (md5sum: busybox on OpenWrt has no cksum.)
node_id() {
	_nid=$(printf '%s' "${1%%#*}" | md5sum 2>/dev/null | cut -c1-8)
	echo "${_nid:-unknown}"
}

ensure_dirs() {
	umask 077
	mkdir -p "$WD_STATE_DIR" "$TMP_DIR" 2>/dev/null
	chmod 700 "$WD_STATE_DIR" "$TMP_DIR" 2>/dev/null
}

# Atomically replace a file with stdin.
write_atomic() { # path
	_t="$1.tmp.$$"
	cat >"$_t" && chmod 600 "$_t" && mv -f "$_t" "$1"
}

# ---------------------------------------------------------------- config ---

cfg_defaults() {
	C_ENABLED=1
	C_PODKOP_SECTION=main
	C_API_BASE=https://api.scat-search.ru/api
	C_SUB_QUERY='format=raw&rename=false'
	C_CHECK_INTERVAL=30
	C_TUNNEL_FAIL_THRESHOLD=3
	C_TUNNEL_OK_THRESHOLD=2
	C_PODKOP_FAIL_THRESHOLD=3
	C_WAN_INTERFACE=wan
	C_INTERNET_TARGET='77.88.8.8 1.1.1.1 8.8.8.8'
	C_DNS_TEST_DOMAIN=google.com
	C_DIRECT_DNS=''
	C_TUNNEL_TEST_URL='https://www.gstatic.com/generate_204 https://cp.cloudflare.com/generate_204'
	C_TUNNEL_TEST_TIMEOUT_MS=8000
	C_CLASH_API=''
	C_CHECK_FULL_PATH=1
	C_FULL_PATH_URL=https://ip.podkop.fyi/check
	C_CANDIDATE_TEST_URL=https://www.cloudflare.com/cdn-cgi/trace
	C_CANDIDATE_EXPECT=h=www.cloudflare.com
	C_CANDIDATE_TEST_TIMEOUT=15
	C_CANDIDATE_TEST_PASSES=2
	C_MAX_CANDIDATES=20
	C_MAX_APPLIES_PER_ROUND=3
	C_MIN_MEM_AVAILABLE_KB=8192
	C_SETTLE_TIME=20
	C_VERIFY_ATTEMPTS=4
	C_VERIFY_INTERVAL=15
	C_API_TIMEOUT=20
	C_API_RETRIES=3
	C_API_BACKOFF=15
	C_SCAN_POLL_INTERVAL=15
	C_SCAN_WAIT_MAX=900
	C_REFRESH_INTERVAL=600
	C_RESTART_MIN_INTERVAL=60
	C_RESTART_MAX_PER_HOUR=6
	C_BOOT_GRACE=120
	C_PERSIST_LKG=1
	C_API_CHECK_INTERVAL=600
	C_WAN_REPAIR=1
	C_WAN_FAIL_THRESHOLD=3
	C_WAN_SETTLE=60
	C_WAN_REPAIR_BACKOFF=120
	C_WAN_REPAIR_MAX_INTERVAL=1800
	C_WAN_RX_ACTIVE_BYTES=65536
	C_WIFI_REPAIR=1
	C_WIFI_STALL_CHECKS=10
	C_EVENT_LOG=1
	C_EVENT_LOG_MAX_KB=64
	C_NOTIFY=1
	C_TG_TOKEN=''
	C_TG_CHAT=''
}

# Explicit whitelist: config values are never eval'd.
cfg_assign() { # name value
	case "$1" in
	enabled) C_ENABLED=$2 ;; podkop_section) C_PODKOP_SECTION=$2 ;;
	api_base) C_API_BASE=$2 ;; sub_query) C_SUB_QUERY=$2 ;;
	check_interval) C_CHECK_INTERVAL=$2 ;; tunnel_fail_threshold) C_TUNNEL_FAIL_THRESHOLD=$2 ;;
	tunnel_ok_threshold) C_TUNNEL_OK_THRESHOLD=$2 ;; podkop_fail_threshold) C_PODKOP_FAIL_THRESHOLD=$2 ;;
	wan_interface) C_WAN_INTERFACE=$2 ;; internet_target) C_INTERNET_TARGET=$2 ;;
	dns_test_domain) C_DNS_TEST_DOMAIN=$2 ;; direct_dns) C_DIRECT_DNS=$2 ;;
	tunnel_test_url) C_TUNNEL_TEST_URL=$2 ;; tunnel_test_timeout_ms) C_TUNNEL_TEST_TIMEOUT_MS=$2 ;;
	clash_api) C_CLASH_API=$2 ;; check_full_path) C_CHECK_FULL_PATH=$2 ;;
	full_path_url) C_FULL_PATH_URL=$2 ;; candidate_test_url) C_CANDIDATE_TEST_URL=$2 ;;
	candidate_expect) C_CANDIDATE_EXPECT=$2 ;; candidate_test_timeout) C_CANDIDATE_TEST_TIMEOUT=$2 ;;
	candidate_test_passes) C_CANDIDATE_TEST_PASSES=$2 ;; max_candidates) C_MAX_CANDIDATES=$2 ;;
	max_applies_per_round) C_MAX_APPLIES_PER_ROUND=$2 ;; min_mem_available_kb) C_MIN_MEM_AVAILABLE_KB=$2 ;;
	settle_time) C_SETTLE_TIME=$2 ;; verify_attempts) C_VERIFY_ATTEMPTS=$2 ;;
	verify_interval) C_VERIFY_INTERVAL=$2 ;; api_timeout) C_API_TIMEOUT=$2 ;;
	api_retries) C_API_RETRIES=$2 ;; api_backoff) C_API_BACKOFF=$2 ;;
	scan_poll_interval) C_SCAN_POLL_INTERVAL=$2 ;; scan_wait_max) C_SCAN_WAIT_MAX=$2 ;;
	refresh_interval) C_REFRESH_INTERVAL=$2 ;; restart_min_interval) C_RESTART_MIN_INTERVAL=$2 ;;
	restart_max_per_hour) C_RESTART_MAX_PER_HOUR=$2 ;; boot_grace) C_BOOT_GRACE=$2 ;;
	persist_lkg) C_PERSIST_LKG=$2 ;; api_check_interval) C_API_CHECK_INTERVAL=$2 ;;
	wan_repair) C_WAN_REPAIR=$2 ;; wan_fail_threshold) C_WAN_FAIL_THRESHOLD=$2 ;;
	wan_settle) C_WAN_SETTLE=$2 ;; wan_repair_backoff) C_WAN_REPAIR_BACKOFF=$2 ;;
	wan_repair_max_interval) C_WAN_REPAIR_MAX_INTERVAL=$2 ;; wan_rx_active_bytes) C_WAN_RX_ACTIVE_BYTES=$2 ;;
	wifi_repair) C_WIFI_REPAIR=$2 ;; wifi_stall_checks) C_WIFI_STALL_CHECKS=$2 ;;
	event_log) C_EVENT_LOG=$2 ;; event_log_max_kb) C_EVENT_LOG_MAX_KB=$2 ;;
	notify) C_NOTIFY=$2 ;; telegram_token) C_TG_TOKEN=$2 ;; telegram_chat_id) C_TG_CHAT=$2 ;;
	*) log warning "unknown config option '$1' ignored" ;;
	esac
}

# Clamp an integer config variable into [min,max]; fall back to default if invalid.
cfg_int() { # varname default min max
	eval "_v=\${$1}"
	if ! is_uint "$_v"; then
		log warning "invalid value for ${1#C_}, using $2"
		_v=$2
	fi
	[ "$_v" -lt "$3" ] && _v=$3
	[ "$_v" -gt "$4" ] && _v=$4
	eval "$1=\$_v"
}

load_config() {
	cfg_defaults
	# One uci call. Lines look like: pkg.main.opt='v'  or  pkg.main.list='a' 'b'
	_out=$(uci -q show "$WD_PKG.main" 2>/dev/null)
	while IFS= read -r _line; do
		_key=${_line%%=*}
		_val=${_line#*=}
		[ "$_key" = "$_line" ] && continue
		[ "$_key" = "$WD_PKG.main" ] && continue
		_opt=${_key##*.}
		_val=$(printf '%s' "$_val" | sed "s/^'//; s/'\$//; s/' '/ /g")
		cfg_assign "$_opt" "$_val"
	done <<EOF
$_out
EOF

	cfg_int C_CHECK_INTERVAL 30 10 3600
	cfg_int C_TUNNEL_FAIL_THRESHOLD 3 1 100
	cfg_int C_TUNNEL_OK_THRESHOLD 2 1 100
	cfg_int C_PODKOP_FAIL_THRESHOLD 3 1 100
	cfg_int C_TUNNEL_TEST_TIMEOUT_MS 8000 1000 30000
	cfg_int C_CANDIDATE_TEST_TIMEOUT 15 5 120
	cfg_int C_CANDIDATE_TEST_PASSES 2 1 5
	cfg_int C_MAX_CANDIDATES 20 1 50
	cfg_int C_MAX_APPLIES_PER_ROUND 3 1 10
	cfg_int C_MIN_MEM_AVAILABLE_KB 8192 0 1048576
	cfg_int C_SETTLE_TIME 20 1 300
	cfg_int C_VERIFY_ATTEMPTS 4 1 20
	cfg_int C_VERIFY_INTERVAL 15 1 300
	cfg_int C_API_TIMEOUT 20 5 120
	cfg_int C_API_RETRIES 3 1 10
	cfg_int C_API_BACKOFF 15 1 600
	cfg_int C_SCAN_POLL_INTERVAL 15 5 300
	cfg_int C_SCAN_WAIT_MAX 900 60 3600
	# The API enforces a 10-minute refresh cooldown; never go below it.
	cfg_int C_REFRESH_INTERVAL 600 600 86400
	cfg_int C_RESTART_MIN_INTERVAL 60 10 3600
	cfg_int C_RESTART_MAX_PER_HOUR 6 1 60
	cfg_int C_BOOT_GRACE 120 0 1800
	cfg_int C_API_CHECK_INTERVAL 600 60 86400
	cfg_int C_WAN_FAIL_THRESHOLD 3 2 100
	cfg_int C_WAN_SETTLE 60 10 600
	cfg_int C_WAN_REPAIR_BACKOFF 120 60 3600
	cfg_int C_WAN_REPAIR_MAX_INTERVAL 1800 300 86400
	cfg_int C_WAN_RX_ACTIVE_BYTES 65536 1024 1073741824
	cfg_int C_WIFI_STALL_CHECKS 10 3 1000
	cfg_int C_EVENT_LOG_MAX_KB 64 8 1024
	# The token ends up in a URL: accept only the documented formats (never log it).
	if [ -n "$C_TG_TOKEN" ] && ! printf '%s' "$C_TG_TOKEN" | grep -Eq '^[0-9]{1,20}:[A-Za-z0-9_-]{20,100}$'; then
		log err "telegram_token has an invalid format; notifications disabled"
		C_TG_TOKEN=''
	fi
	if [ -n "$C_TG_CHAT" ] && ! printf '%s' "$C_TG_CHAT" | grep -Eq '^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,64})$'; then
		log err "telegram_chat_id has an invalid format; notifications disabled"
		C_TG_CHAT=''
	fi

	case "$C_API_BASE" in
	https://*) ;;
	*)
		log err "api_base must be https://, using default"
		C_API_BASE=https://api.scat-search.ru/api
		;;
	esac
	if ! printf '%s' "$C_API_BASE" | grep -Eq '^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~/-]*)?$'; then
		log err "api_base is malformed, using default"
		C_API_BASE=https://api.scat-search.ru/api
	fi
	C_API_BASE=${C_API_BASE%/}
	if ! printf '%s' "$C_SUB_QUERY" | grep -Eq '^[A-Za-z0-9=&_.-]*$'; then
		log err "sub_query is malformed, using default"
		C_SUB_QUERY='format=raw&rename=false'
	fi
	C_SEC=$C_PODKOP_SECTION
	printf '%s' "$C_SEC" | grep -Eq '^[A-Za-z0-9_]+$' || C_SEC=main
}

# ----------------------------------------------------------------- state ---

state_defaults() {
	S_STATE=MONITOR S_PHASE='' S_NEXT_AT=0 S_FAIL_N=0 S_OK_N=0 S_PK_FAIL_N=0
	S_ATTEMPT=0 S_CAND_IDX=0 S_APPLIES=0 S_VERIFY_N=0 S_LAST_REFRESH_AT=''
	S_DEADLINE=0 S_RESTARTS='' S_LAST_CLASS='' S_LAST_API_AT=0 S_API_OK=''
	S_REC_STARTED=0 S_CYCLE=0 S_FAILED_IDS='' S_LAST_QCHECK=0 S_NOTE=''
	S_APPLIED_ID='' S_D_SUMMARY='' S_DUE_AT=0 S_SELF_AT=0 S_DNS_ESC=0
	S_WAN_AT=0 S_WAN_FAIL_N=0 S_WAN_FIXES=0 S_WAN_REPAIR_AT=0 S_WAN_RX='' S_WAN_NOTE=''
	S_WAN_TRAFFIC=0 S_WAN_SUSPECT=0 S_WAN_DOWN_AT=0 S_WIFI_AT=0 S_NOTIFY_AT=0 S_NOTIFY_FAILS=0
	S_NO_NODE_AT=0
}

# Known keys only; values are plain tokens written by save_state.
load_state() {
	state_defaults
	S_FRESH=1
	[ -f "$STATE_FILE" ] || return 0
	S_FRESH=0
	while IFS='=' read -r _k _v; do
		case "$_k" in
		STATE) S_STATE=$_v ;; PHASE) S_PHASE=$_v ;; NEXT_AT) S_NEXT_AT=$_v ;;
		FAIL_N) S_FAIL_N=$_v ;; OK_N) S_OK_N=$_v ;; PK_FAIL_N) S_PK_FAIL_N=$_v ;;
		ATTEMPT) S_ATTEMPT=$_v ;; CAND_IDX) S_CAND_IDX=$_v ;; APPLIES) S_APPLIES=$_v ;;
		VERIFY_N) S_VERIFY_N=$_v ;; LAST_REFRESH_AT) S_LAST_REFRESH_AT=$_v ;;
		DEADLINE) S_DEADLINE=$_v ;; RESTARTS) S_RESTARTS=$_v ;; LAST_CLASS) S_LAST_CLASS=$_v ;;
		LAST_API_AT) S_LAST_API_AT=$_v ;; API_OK) S_API_OK=$_v ;; REC_STARTED) S_REC_STARTED=$_v ;;
		CYCLE) S_CYCLE=$_v ;; FAILED_IDS) S_FAILED_IDS=$_v ;; LAST_QCHECK) S_LAST_QCHECK=$_v ;;
		NOTE) S_NOTE=$_v ;; APPLIED_ID) S_APPLIED_ID=$_v ;; D_SUMMARY) S_D_SUMMARY=$_v ;;
		DUE_AT) S_DUE_AT=$_v ;; SELF_AT) S_SELF_AT=$_v ;; DNS_ESC) S_DNS_ESC=$_v ;;
		WAN_AT) S_WAN_AT=$_v ;; WAN_FAIL_N) S_WAN_FAIL_N=$_v ;; WAN_FIXES) S_WAN_FIXES=$_v ;;
		WAN_REPAIR_AT) S_WAN_REPAIR_AT=$_v ;; WAN_RX) S_WAN_RX=$_v ;; WAN_NOTE) S_WAN_NOTE=$_v ;;
		WAN_TRAFFIC) S_WAN_TRAFFIC=$_v ;; WAN_SUSPECT) S_WAN_SUSPECT=$_v ;; WAN_DOWN_AT) S_WAN_DOWN_AT=$_v ;;
		WIFI_AT) S_WIFI_AT=$_v ;; NOTIFY_AT) S_NOTIFY_AT=$_v ;; NOTIFY_FAILS) S_NOTIFY_FAILS=$_v ;;
		NO_NODE_AT) S_NO_NODE_AT=$_v ;;
		esac
	done <"$STATE_FILE"
	for _n in NEXT_AT FAIL_N OK_N PK_FAIL_N ATTEMPT CAND_IDX APPLIES VERIFY_N DEADLINE \
		LAST_API_AT REC_STARTED CYCLE LAST_QCHECK DUE_AT SELF_AT DNS_ESC WAN_AT WAN_FAIL_N \
		WAN_FIXES WAN_REPAIR_AT WAN_TRAFFIC WAN_SUSPECT WAN_DOWN_AT WIFI_AT NOTIFY_AT NOTIFY_FAILS \
		NO_NODE_AT; do
		eval "_v=\$S_$_n"
		is_uint "$_v" || eval "S_$_n=0"
	done
	is_uint "$S_LAST_REFRESH_AT" || S_LAST_REFRESH_AT=''
	is_uint "$S_WAN_RX" || S_WAN_RX=''
	return 0
}

save_state() {
	{
		echo "STATE=$S_STATE"
		echo "PHASE=$S_PHASE"
		echo "NEXT_AT=$S_NEXT_AT"
		echo "FAIL_N=$S_FAIL_N"
		echo "OK_N=$S_OK_N"
		echo "PK_FAIL_N=$S_PK_FAIL_N"
		echo "ATTEMPT=$S_ATTEMPT"
		echo "CAND_IDX=$S_CAND_IDX"
		echo "APPLIES=$S_APPLIES"
		echo "VERIFY_N=$S_VERIFY_N"
		echo "LAST_REFRESH_AT=$S_LAST_REFRESH_AT"
		echo "DEADLINE=$S_DEADLINE"
		echo "RESTARTS=$S_RESTARTS"
		echo "LAST_CLASS=$S_LAST_CLASS"
		echo "LAST_API_AT=$S_LAST_API_AT"
		echo "API_OK=$S_API_OK"
		echo "REC_STARTED=$S_REC_STARTED"
		echo "CYCLE=$S_CYCLE"
		echo "FAILED_IDS=$S_FAILED_IDS"
		echo "LAST_QCHECK=$S_LAST_QCHECK"
		echo "NOTE=$S_NOTE"
		echo "APPLIED_ID=$S_APPLIED_ID"
		echo "D_SUMMARY=$S_D_SUMMARY"
		echo "DUE_AT=$S_DUE_AT"
		echo "SELF_AT=$S_SELF_AT"
		echo "DNS_ESC=$S_DNS_ESC"
		echo "WAN_AT=$S_WAN_AT"
		echo "WAN_FAIL_N=$S_WAN_FAIL_N"
		echo "WAN_FIXES=$S_WAN_FIXES"
		echo "WAN_REPAIR_AT=$S_WAN_REPAIR_AT"
		echo "WAN_RX=$S_WAN_RX"
		echo "WAN_NOTE=$S_WAN_NOTE"
		echo "WAN_TRAFFIC=$S_WAN_TRAFFIC"
		echo "WAN_SUSPECT=$S_WAN_SUSPECT"
		echo "WAN_DOWN_AT=$S_WAN_DOWN_AT"
		echo "WIFI_AT=$S_WIFI_AT"
		echo "NOTIFY_AT=$S_NOTIFY_AT"
		echo "NOTIFY_FAILS=$S_NOTIFY_FAILS"
		echo "NO_NODE_AT=$S_NO_NODE_AT"
	} | write_atomic "$STATE_FILE"
}

set_state() { # new_state
	S_STATE=$1
	S_ATTEMPT=0
}

# ------------------------------------------------------- process control ---

# Run a command with a hard time limit (busybox has no `timeout`).
run_with_timeout() { # seconds cmd...
	_secs=$1
	shift
	# Children must not inherit the lock fds (8, 9): an orphan would keep the
	# service lock held after this process exits.
	"$@" 8>&- 9>&- &
	_pid=$!
	(
		sleep "$_secs" &
		_sp=$!
		trap 'kill "$_sp" 2>/dev/null; exit 0' TERM
		wait "$_sp"
		kill -TERM "$_pid" 2>/dev/null
		sleep 2
		kill -KILL "$_pid" 2>/dev/null
	) >/dev/null 2>&1 8>&- 9>&- &
	_killer=$!
	wait "$_pid"
	_rc=$?
	kill "$_killer" 2>/dev/null
	wait "$_killer" 2>/dev/null
	return "$_rc"
}

mem_available_kb() {
	awk '/^MemAvailable:/ {print $2; f=1} END {if (!f) print 0}' "$WD_MEMINFO_FILE" 2>/dev/null || echo 0
}

# Restart budget shared by health restarts and node switches.
prune_restarts() {
	_now=$(now_s)
	_keep=''
	for _t in $S_RESTARTS; do
		is_uint "$_t" || continue
		[ $((_now - _t)) -lt 3600 ] && _keep="$_keep $_t"
	done
	S_RESTARTS=${_keep# }
}

# Prints seconds until a restart is allowed (0 = allowed now).
restart_wait() {
	prune_restarts
	_now=$(now_s)
	_n=0
	_last=''
	_first=''
	for _t in $S_RESTARTS; do
		_n=$((_n + 1))
		[ -z "$_first" ] && _first=$_t
		_last=$_t
	done
	_w=0
	if [ -n "$_last" ] && [ $((_now - _last)) -lt "$C_RESTART_MIN_INTERVAL" ]; then
		_w=$((C_RESTART_MIN_INTERVAL - (_now - _last)))
	fi
	if [ "$_n" -ge "$C_RESTART_MAX_PER_HOUR" ]; then
		_w2=$((3600 - (_now - _first)))
		[ "$_w2" -gt "$_w" ] && _w=$_w2
	fi
	echo "$_w"
}

record_restart() {
	prune_restarts
	S_RESTARTS="${S_RESTARTS:+$S_RESTARTS }$(now_s)"
}
