# podkop-watchdog: Scat API client and subscription parsing.
# All responses are untrusted input.
# shellcheck shell=sh disable=SC2034 # globals are shared across sourced modules

API_MAX_BYTES=262144

api_host() {
	_h=${C_API_BASE#https://}
	echo "${_h%%/*}"
}

# Resolve via a direct DNS server so recovery never depends on sing-box DNS.
# Rejects fakeip/loopback/unspecified answers.
resolve_direct() { # host -> prints IPv4
	nslookup "$1" "$(direct_dns)" 2>/dev/null | awk '
		/^Name:/ {named=1; next}
		named && /^Address/ {
			a=$NF; sub(/^.*: */, "", a)
			if (a ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && a !~ /^(198\.1[89]\.|127\.|0\.)/) {print a; exit}
		}'
}

# api_req METHOD PATH
# Sets API_CODE (HTTP status or 000), API_CURL_RC, API_RETRY_AFTER; body in $API_BODY.
api_req() {
	API_BODY="$TMP_DIR/api.body"
	_hdr="$TMP_DIR/api.hdr"
	rm -f "$API_BODY" "$_hdr"
	_host=$(api_host)
	_ip=$(resolve_direct "$_host")
	_method=$1
	_url="$C_API_BASE$2"
	if [ -n "$_ip" ]; then
		set -- --resolve "$_host:443:$_ip"
	else
		set --
	fi
	if [ "$_method" = POST ]; then
		set -- "$@" -X POST --data ''
	fi
	API_CODE=$(curl -sS --proto '=https' --tlsv1.2 --connect-timeout 10 \
		--max-time "$C_API_TIMEOUT" --max-filesize "$API_MAX_BYTES" \
		-H 'Accept: application/json, text/plain' \
		"$@" -o "$API_BODY" -D "$_hdr" -w '%{http_code}' "$_url" 2>/dev/null)
	API_CURL_RC=$?
	is_uint "$API_CODE" || API_CODE=000
	API_RETRY_AFTER=$(awk -F': *' 'tolower($1)=="retry-after" {gsub(/\r/, "", $2); print $2; exit}' \
		"$_hdr" 2>/dev/null)
	is_uint "$API_RETRY_AFTER" || API_RETRY_AFTER=''
	rm -f "$_hdr"
	[ "$API_CURL_RC" -eq 0 ] && [ "$API_CODE" = 200 ]
}

# Network error, timeout, rate limit or server error: worth retrying later.
api_transient() {
	[ "$API_CURL_RC" -ne 0 ] && return 0
	case "$API_CODE" in 000 | 408 | 429 | 5??) return 0 ;; esac
	return 1
}

api_err_desc() { echo "http=$API_CODE curl=$API_CURL_RC"; }

json_field() { # field  (reads $API_BODY)
	jq -r --arg f "$1" '.[$f] | if . == null then empty else tostring end' "$API_BODY" 2>/dev/null
}

# A vless:// URL we are willing to hand to uci and sing-box.
# User part must be a UUID; host is a DNS name, IPv4 or bracketed IPv6;
# the rest is limited to URL-safe characters (no quotes, $, \, `, spaces).
VLESS_RE='^vless://[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}@([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}(/[A-Za-z0-9._~%-]*)?(\?[][A-Za-z0-9._~:/?@!&()*+,;=%-]*)?$'

valid_vless() {
	[ "${#1}" -le 2048 ] || return 1
	printf '%s\n' "$1" | grep -Eq "$VLESS_RE" || return 1
	_hp=${1#*@}
	_hp=${_hp%%[/?#]*}
	_port=${_hp##*:}
	is_uint "$_port" && [ "$_port" -ge 1 ] && [ "$_port" -le 65535 ]
}

# parse_subscription INFILE OUTFILE -> prints "valid rejected"
# Accepts raw text or base64 (the API default). Dedupes, caps at max_candidates.
parse_subscription() {
	_in=$1
	_out=$2
	_plain="$TMP_DIR/sub.plain"
	if grep -q '://' "$_in" 2>/dev/null; then
		tr -d '\r' <"$_in" >"$_plain"
	else
		tr -d '\r\n ' <"$_in" | base64 -d 2>/dev/null | tr -d '\r' >"$_plain" || : >"$_plain"
	fi
	: >"$_out.tmp"
	_valid=0
	_rej=0
	while IFS= read -r _l || [ -n "$_l" ]; do
		# Display names (#fragment) are not needed and are dropped.
		_l=${_l%%#*}
		[ -z "$_l" ] && continue
		if valid_vless "$_l"; then
			if [ "$_valid" -lt "$C_MAX_CANDIDATES" ] && ! grep -qxF -- "$_l" "$_out.tmp"; then
				printf '%s\n' "$_l" >>"$_out.tmp"
				_valid=$((_valid + 1))
			fi
		else
			_rej=$((_rej + 1))
		fi
	done <"$_plain"
	rm -f "$_plain"
	chmod 600 "$_out.tmp" && mv -f "$_out.tmp" "$_out"
	echo "$_valid $_rej"
}
