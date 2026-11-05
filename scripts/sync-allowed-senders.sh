#!/usr/bin/env bash
set -euo pipefail

STAGED="/var/lib/central-syslog/allowed_senders.staged"
TARGET="/etc/rsyslog.d/15-allowed-senders.conf"
BACKUP="/var/lib/central-syslog/15-allowed-senders.conf.bak"

if [ ! -f "$STAGED" ]; then
    exit 1
fi

cp -f "$TARGET" "$BACKUP" 2>/dev/null || true
install -o root -g root -m 0644 "$STAGED" "$TARGET"

if rsyslogd -N1 >/dev/null 2>&1; then
    systemctl reload-or-restart rsyslog
    exit 0
else
    if [ -f "$BACKUP" ]; then
        install -o root -g root -m 0644 "$BACKUP" "$TARGET"
    fi
    exit 2
fi
