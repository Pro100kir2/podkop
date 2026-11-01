#!/bin/sh
# Install podkop-watchdog on an OpenWrt router (opkg or apk based, any release).
#
#   sh install.sh /tmp/podkop-watchdog_1.1.0_all.ipk
#
# The .ipk is only used as an archive, so this also works where opkg is absent
# (OpenWrt 25.x with apk). An existing /etc/config/podkop-watchdog is kept.
# If anything fails after the service was stopped, the previous version is
# restored and started again.
set -eu
umask 022 # never inherit a stricter umask: it would change the mode of the target root

PKG=${1:?usage: sh install.sh <podkop-watchdog_*_all.ipk>}
ROOT=${INSTALL_ROOT:-/} # tests install into a scratch directory
[ -r "$PKG" ] || {
	echo "cannot read $PKG" >&2
	exit 1
}

for t in jq curl tar gzip df du awk; do
	command -v "$t" >/dev/null 2>&1 || {
		echo "missing '$t': install it first (opkg install $t  /  apk add $t)" >&2
		exit 1
	}
done

W=$(mktemp -d /tmp/podkop-watchdog-install.XXXXXX)
STOPPED=0 DONE=0
finish() {
	_rc=$?
	if [ "$DONE" != 1 ]; then
		echo "install failed (status $_rc): restoring the previous version" >&2
		[ -s "$W/backup.tar" ] && tar -xf "$W/backup.tar" -C "$ROOT" 2>/dev/null
		[ "$STOPPED" = 1 ] && [ "$ROOT" = / ] && /etc/init.d/podkop-watchdog start 2>/dev/null
	fi
	rm -rf "$W"
	exit "$_rc"
}
trap finish EXIT

tar -xzf "$PKG" -C "$W" ./data.tar.gz ./control.tar.gz
mkdir -p "$W/root"
chmod 755 "$W/root"
tar -xzf "$W/data.tar.gz" -C "$W/root"
if [ -e "$ROOT/etc/config/podkop-watchdog" ]; then
	rm -f "$W/root/etc/config/podkop-watchdog" # keep the user's configuration
fi

# Enough room on the target filesystem (twice the payload: new files plus a
# restorable copy of the old ones) before anything is touched.
mkdir -p "$ROOT/usr/lib"
need=$(du -sk "$W/root" | awk '{print $1}')
free=$(df -Pk "$ROOT/usr/lib" | awk 'NR==2 {print $4}')
if [ -n "$free" ] && [ "$free" -lt $((need * 2 + 64)) ]; then
	echo "not enough free space on the router (${free} KB free, ${need} KB package): free some space first" >&2
	DONE=1
	exit 1
fi

# Copy of the current installation, for the automatic restore above.
(cd "$ROOT" && tar -cf "$W/backup.tar" usr/lib/podkop-watchdog usr/bin/podkop-watchdog \
	etc/init.d/podkop-watchdog lib/upgrade/keep.d/podkop-watchdog 2>/dev/null) || : >"$W/backup.tar"

if [ "$ROOT" = / ] && [ -x /etc/init.d/podkop-watchdog ]; then
	/etc/init.d/podkop-watchdog stop 2>/dev/null || true
	STOPPED=1
fi
# Top-level entries only (no "./"): an archive member for the root directory
# itself would change the mode of the target root.
(cd "$W/root" && tar -cf - ./*) | tar -xf - -C "$ROOT"
[ -e "$ROOT/etc/config/podkop-watchdog" ] && chmod 600 "$ROOT/etc/config/podkop-watchdog"

if [ "$ROOT" = / ]; then
	/etc/init.d/podkop-watchdog enable
	/etc/init.d/podkop-watchdog restart
	echo
	/usr/bin/podkop-watchdog selfcheck || true
fi
DONE=1
