#!/bin/sh
# Copy podkop-watchdog to an OpenWrt router over SSH (no sftp-server needed).
# Installs files only; it does NOT enable or start the service.
#
#   scripts/deploy.sh root@192.168.1.1
#
# An existing /etc/config/podkop-watchdog is never overwritten.
set -eu

TARGET=${1:?usage: $0 user@router}
ROOT=$(cd "$(dirname "$0")/.." && pwd)/files
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10"

put() { # local_rel remote_path mode
	$SSH "$TARGET" "mkdir -p '$(dirname "$2")' && cat > '$2.new' && chmod $3 '$2.new' && mv -f '$2.new' '$2'" <"$ROOT/$1"
	echo "installed $2"
}

for m in common checks api candidate machine; do
	put "usr/lib/podkop-watchdog/$m.sh" "/usr/lib/podkop-watchdog/$m.sh" 644
done
put usr/bin/podkop-watchdog /usr/bin/podkop-watchdog 755
put etc/init.d/podkop-watchdog /etc/init.d/podkop-watchdog 755
put lib/upgrade/keep.d/podkop-watchdog /lib/upgrade/keep.d/podkop-watchdog 644

if $SSH "$TARGET" "[ -e /etc/config/podkop-watchdog ]"; then
	echo "kept existing /etc/config/podkop-watchdog"
else
	put etc/config/podkop-watchdog /etc/config/podkop-watchdog 600
fi

echo
echo "Files installed. Next (on the router):"
echo "  podkop-watchdog diagnose          # read-only health report"
echo "  podkop-watchdog test-candidates   # read-only isolated node tests"
echo "  /etc/init.d/podkop-watchdog enable && /etc/init.d/podkop-watchdog start"
