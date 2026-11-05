#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="/var/lib/central-syslog/backups"
TIMESTAMP=$(date -u +"%Y%m%d-%H%M%S")
mkdir -p "$BACKUP_DIR"

case "${1:-backup}" in
    backup)
        ARCHIVE="${BACKUP_DIR}/sentinellog-backup-${TIMESTAMP}.tar.gz"
        TMP_DIR=$(mktemp -d)
        mysqldump -u root --single-transaction syslog_portal > "${TMP_DIR}/syslog_portal.sql"
        sqlite3 /var/lib/central-syslog/index/syslog_hot.sqlite ".backup '${TMP_DIR}/syslog_hot.sqlite'"
        cp -a /etc/rsyslog.d "${TMP_DIR}/rsyslog.d"
        cp -a /var/www/syslog-portal/.env "${TMP_DIR}/portal.env"
        tar -czf "$ARCHIVE" -C "$TMP_DIR" .
        rm -rf "$TMP_DIR"
        chmod 0600 "$ARCHIVE"
        echo "Backup created: $ARCHIVE"
        ;;
    restore)
        ARCHIVE="${2:-}"
        if [ -z "$ARCHIVE" ] || [ ! -f "$ARCHIVE" ]; then
            echo "Usage: $0 restore /path/to/backup.tar.gz"
            exit 1
        fi
        TMP_DIR=$(mktemp -d)
        tar -xzf "$ARCHIVE" -C "$TMP_DIR"
        systemctl stop syslog-indexer
        mysql -u root syslog_portal < "${TMP_DIR}/syslog_portal.sql"
        cp -f "${TMP_DIR}/syslog_hot.sqlite" /var/lib/central-syslog/index/syslog_hot.sqlite
        chown www-data:www-data /var/lib/central-syslog/index/syslog_hot.sqlite
        systemctl start syslog-indexer
        rm -rf "$TMP_DIR"
        echo "Restore completed from: $ARCHIVE"
        ;;
    *)
        echo "Usage: $0 {backup|restore <archive.tar.gz>}"
        exit 1
        ;;
esac
