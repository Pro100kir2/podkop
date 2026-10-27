#!/bin/sh
# Remove podkop-watchdog from the router. Podkop's own configuration is left
# exactly as it is now (the watchdog never keeps hidden changes elsewhere).
#
#   scripts/uninstall.sh root@192.168.1.1 [--purge]
#
# --purge also removes /etc/config/podkop-watchdog and the stored
# last-known-good node (/etc/podkop-watchdog).
set -eu

TARGET=${1:?usage: $0 user@router [--purge]}
PURGE=${2:-}

ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET" "
/etc/init.d/podkop-watchdog stop 2>/dev/null
/etc/init.d/podkop-watchdog disable 2>/dev/null
rm -f /etc/init.d/podkop-watchdog /usr/bin/podkop-watchdog /lib/upgrade/keep.d/podkop-watchdog
rm -rf /usr/lib/podkop-watchdog /tmp/podkop-watchdog
rm -f /var/lock/podkop-watchdog.lock /var/lock/podkop-watchdog.lock.test
if [ '$PURGE' = --purge ]; then rm -rf /etc/config/podkop-watchdog /etc/podkop-watchdog; fi
echo removed
"
