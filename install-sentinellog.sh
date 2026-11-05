#!/usr/bin/env bash
# ==============================================================================
# SentinelLog Centralized Syslog Server & Laravel Web Portal - Automated Installer
# Repository: https://github.com/rana442/SentinelLog
# Target OS: Ubuntu Server 24.04 LTS (Noble Numbat)
# Usage:
#   sudo bash install-sentinellog.sh
# Optional Environment Overrides:
#   DOMAIN_NAME="syslog.example.com" ENABLE_CERTBOT="true" \
#   SERVER_IP="203.0.113.10" WAZUH_ENABLE="true" WAZUH_MANAGER_IP="203.0.113.5" \
#   sudo -E bash install-sentinellog.sh
# ==============================================================================
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Please run this installer as root (sudo bash $0)"
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# --- Configurable Parameters (with automatic detection defaults) ---
SERVER_IP="${SERVER_IP:-$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)}"
SERVER_IP="${SERVER_IP:-$(hostname -I | awk '{print $1}')}"
SERVER_HOSTNAME="${SERVER_HOSTNAME:-$(hostname -s)}"
DOMAIN_NAME="${DOMAIN_NAME:-}"
ENABLE_CERTBOT="${ENABLE_CERTBOT:-false}"
PORTAL_HOST="${DOMAIN_NAME:-${SERVER_IP}}"
SSH_PORT="${SSH_PORT:-$(ss -tlnp | awk '/sshd/ {split($4,a,":"); print a[length(a)]}' | head -n1)}"
SSH_PORT="${SSH_PORT:-22}"

DB_NAME="${DB_NAME:-syslog_portal}"
DB_USER="${DB_USER:-syslog_app}"
DB_PASS="${DB_PASS:-SyslogP0rtal_2026!Sec}"

WAZUH_ENABLE="${WAZUH_ENABLE:-false}"
WAZUH_MANAGER_IP="${WAZUH_MANAGER_IP:-}"
WAZUH_VERSION="${WAZUH_VERSION:-4.14.9-1}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-central-syslog-${SERVER_HOSTNAME}}"

INSTALL_HWE_KERNEL="${INSTALL_HWE_KERNEL:-true}"

echo "=================================================================="
echo " SentinelLog Automated Installer Starting"
echo " Server IP:        ${SERVER_IP}"
echo " Portal Host/FQDN: ${PORTAL_HOST} (Certbot SSL: ${ENABLE_CERTBOT})"
echo " Hostname:         ${SERVER_HOSTNAME}"
echo " Detected SSH:     ${SSH_PORT}/tcp"
echo " Wazuh Manager:    ${WAZUH_MANAGER_IP} (Enabled: ${WAZUH_ENABLE})"
echo "=================================================================="

# --- Phase 1: OS Hardening, CVE Package Cleanup & Core Packages ---
echo "[1/11] Updating Ubuntu 24.04 packages and installing core stack..."
grep -q '^UseDNS no' /etc/ssh/sshd_config || (echo 'UseDNS no' >> /etc/ssh/sshd_config && systemctl reload ssh || true)

apt-get update -qq
apt-get dist-upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

apt-get install -y -qq \
    nginx mariadb-server redis-server rsyslog-gnutls gnutls-bin \
    php8.3-fpm php8.3-cli php8.3-mysql php8.3-sqlite3 php8.3-redis \
    php8.3-mbstring php8.3-xml php8.3-curl php8.3-zip php8.3-bcmath \
    php8.3-intl php8.3-gd sqlite3 jq git unzip acl logrotate curl netcat-openbsd

# Install standalone Composer binary (avoids vulnerable Ubuntu Universe php-symfony-* deb packages)
if [ ! -x /usr/local/bin/composer ]; then
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    chmod +x /usr/local/bin/composer
fi

# Purge unused CVE-prone build/header/node packages if present
apt-get purge --autoremove -y npm nodejs libnode-dev composer jsonlint \
    linux-headers-generic linux-libc-dev linux-tools-common build-essential 2>/dev/null || true

if [ "${INSTALL_HWE_KERNEL}" = "true" ]; then
    apt-get install -y --no-install-recommends linux-image-generic-hwe-24.04 || true
fi

# --- Phase 2: Directory Hierarchy & Least-Privilege ACLs ---
echo "[2/11] Creating log, index, and backup directories with ACLs..."
mkdir -p /var/log/central-syslog/{hosts,ingest,archive}
mkdir -p /var/lib/central-syslog/{index,backups}
mkdir -p /etc/rsyslog.d/certs
mkdir -p /etc/nginx/ssl
mkdir -p /opt/central-syslog/scripts

chown -R syslog:adm /var/log/central-syslog
chmod 2750 /var/log/central-syslog /var/log/central-syslog/hosts /var/log/central-syslog/ingest /var/log/central-syslog/archive
usermod -aG adm www-data
setfacl -R -m u:www-data:rx,g:adm:rx /var/log/central-syslog
setfacl -R -d -m u:www-data:rx,g:adm:rx /var/log/central-syslog
setfacl -m u:www-data:rwx /var/log/central-syslog/ingest
setfacl -d -m u:www-data:rw /var/log/central-syslog/ingest

touch /var/log/central-syslog/portal-audit.json
chown www-data:adm /var/log/central-syslog/portal-audit.json
chmod 0640 /var/log/central-syslog/portal-audit.json

chown -R www-data:www-data /var/lib/central-syslog
chmod 0750 /var/lib/central-syslog /var/lib/central-syslog/index /var/lib/central-syslog/backups

# --- Phase 3: X.509 TLS Certificates for rsyslog (6514) and Nginx HTTPS (443) ---
echo "[3/11] Generating X.509 CA, Server, and Client TLS certificates..."
if [ ! -f /etc/rsyslog.d/certs/ca.pem ]; then
    openssl genrsa -out /etc/rsyslog.d/certs/ca-key.pem 4096
    openssl req -x509 -new -nodes -key /etc/rsyslog.d/certs/ca-key.pem -sha256 -days 3650 \
        -subj "/C=US/ST=Security/L=SOC/O=SentinelLog/OU=LoggingCA/CN=SentinelLog-Root-CA" \
        -out /etc/rsyslog.d/certs/ca.pem

    cat > /etc/rsyslog.d/certs/server-ext.cnf << EXT
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:${SERVER_HOSTNAME}, DNS:localhost, IP:${SERVER_IP}, IP:127.0.0.1
EXT

    openssl genrsa -out /etc/rsyslog.d/certs/server-key.pem 2048
    openssl req -new -key /etc/rsyslog.d/certs/server-key.pem \
        -subj "/C=US/ST=Security/L=SOC/O=SentinelLog/OU=SyslogReceiver/CN=${SERVER_IP}" \
        -out /etc/rsyslog.d/certs/server.csr
    openssl x509 -req -in /etc/rsyslog.d/certs/server.csr \
        -CA /etc/rsyslog.d/certs/ca.pem -CAkey /etc/rsyslog.d/certs/ca-key.pem -CAcreateserial \
        -out /etc/rsyslog.d/certs/server-cert.pem -days 1825 -sha256 \
        -extfile /etc/rsyslog.d/certs/server-ext.cnf

    openssl genrsa -out /etc/rsyslog.d/certs/client-key.pem 2048
    openssl req -new -key /etc/rsyslog.d/certs/client-key.pem \
        -subj "/C=US/ST=Security/L=SOC/O=SentinelLog/OU=SyslogClient/CN=syslog-client" \
        -out /etc/rsyslog.d/certs/client.csr
    openssl x509 -req -in /etc/rsyslog.d/certs/client.csr \
        -CA /etc/rsyslog.d/certs/ca.pem -CAkey /etc/rsyslog.d/certs/ca-key.pem -CAcreateserial \
        -out /etc/rsyslog.d/certs/client-cert.pem -days 1825 -sha256 \
        -extfile /etc/rsyslog.d/certs/server-ext.cnf
fi

chown -R syslog:adm /etc/rsyslog.d/certs
chmod 0750 /etc/rsyslog.d/certs
chmod 0640 /etc/rsyslog.d/certs/*.pem
setfacl -m u:www-data:rx /etc/rsyslog.d/certs
setfacl -m u:www-data:r /etc/rsyslog.d/certs/ca.pem /etc/rsyslog.d/certs/server-cert.pem /etc/rsyslog.d/certs/client-cert.pem

cp -f /etc/rsyslog.d/certs/server-cert.pem /etc/nginx/ssl/syslog-portal.crt
cp -f /etc/rsyslog.d/certs/server-key.pem /etc/nginx/ssl/syslog-portal.key
chmod 0600 /etc/nginx/ssl/syslog-portal.key
chmod 0644 /etc/nginx/ssl/syslog-portal.crt

# --- Phase 4: AppArmor & rsyslog Central Receiver (UDP 514, TCP 514, TLS 6514) ---
echo "[4/11] Configuring AppArmor and rsyslog central receiver..."
if [ -d /etc/apparmor.d/local ]; then
    cat > /etc/apparmor.d/local/usr.sbin.rsyslogd << 'AA'
  /var/log/central-syslog/ rw,
  /var/log/central-syslog/** rw,
  /etc/rsyslog.d/certs/ r,
  /etc/rsyslog.d/certs/** r,
AA
    if [ -f /etc/apparmor.d/usr.sbin.rsyslogd ]; then
        apparmor_parser -r /etc/apparmor.d/usr.sbin.rsyslogd || true
    fi
fi

cat > /etc/rsyslog.d/10-central-receiver.conf << 'RSYSLOG_CONF'
global(
    preserveFQDN="on"
    maxMessageSize="64k"
    defaultNetstreamDriver="gtls"
    defaultNetstreamDriverCAFile="/etc/rsyslog.d/certs/ca.pem"
    defaultNetstreamDriverCertFile="/etc/rsyslog.d/certs/server-cert.pem"
    defaultNetstreamDriverKeyFile="/etc/rsyslog.d/certs/server-key.pem"
    parser.escapeControlCharactersOnReceive="on"
)

module(load="imudp" threads="2" TimeRequery="8" batchSize="128")
module(
    load="imtcp"
    MaxSessions="500"
    KeepAlive="on"
    KeepAlive.Probes="3"
    KeepAlive.Interval="30"
    KeepAlive.Time="120"
    StreamDriver.Name="gtls"
    StreamDriver.Mode="0"
    StreamDriver.AuthMode="anon"
)

template(name="CentralPerHostFile" type="string"
    string="/var/log/central-syslog/hosts/%fromhost-ip:::secpath-replace%_%hostname:::secpath-replace%/%$year%-%$month%-%$day%/%syslogfacility-text:::secpath-replace%.log"
)

template(name="CentralArchiveFormat" type="string"
    string="%TIMESTAMP% %hostname% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n"
)

template(name="CentralJsonLine" type="list") {
    constant(value="{")
    property(outname="received_at" name="timegenerated" dateFormat="rfc3339" format="jsonf")
    constant(value=",")
    property(outname="reported_at" name="timereported" dateFormat="rfc3339" format="jsonf")
    constant(value=",")
    property(outname="source_ip" name="fromhost-ip" format="jsonf")
    constant(value=",")
    property(outname="hostname" name="hostname" format="jsonf")
    constant(value=",")
    property(outname="facility" name="syslogfacility-text" format="jsonf")
    constant(value=",")
    property(outname="facility_num" name="syslogfacility" format="jsonf")
    constant(value=",")
    property(outname="severity" name="syslogseverity-text" format="jsonf")
    constant(value=",")
    property(outname="severity_num" name="syslogseverity" format="jsonf")
    constant(value=",")
    property(outname="app_name" name="app-name" format="jsonf")
    constant(value=",")
    property(outname="proc_id" name="procid" format="jsonf")
    constant(value=",")
    property(outname="msg_id" name="msgid" format="jsonf")
    constant(value=",")
    property(outname="protocol" name="$!transport" format="jsonf")
    constant(value=",")
    property(outname="message" name="msg" format="jsonf")
    constant(value=",")
    property(outname="raw_message" name="rawmsg" format="jsonf")
    constant(value="}\n")
}

ruleset(name="store_central" queue.type="LinkedList" queue.size="50000" queue.dequeueBatchSize="256" queue.saveOnShutdown="on") {
    action(
        type="omfile"
        dynaFile="CentralPerHostFile"
        template="CentralArchiveFormat"
        dynaFileCacheSize="128"
        dirCreateMode="0750"
        fileCreateMode="0640"
        dirOwner="syslog"
        dirGroup="adm"
        fileOwner="syslog"
        fileGroup="adm"
        asyncWriting="on"
        flushOnTXEnd="off"
        ioBufferSize="64k"
    )
    action(
        type="omfile"
        file="/var/log/central-syslog/ingest/stream.ndjson"
        template="CentralJsonLine"
        fileCreateMode="0640"
        fileOwner="syslog"
        fileGroup="adm"
        asyncWriting="off"
    )
}

ruleset(name="remote_udp") { set $!transport = "UDP"; call store_central stop }
ruleset(name="remote_tcp") { set $!transport = "TCP"; call store_central stop }
ruleset(name="remote_tls") { set $!transport = "TLS"; call store_central stop }

input(type="imudp" port="514" ruleset="remote_udp" RateLimit.Interval="5" RateLimit.Burst="20000")
input(type="imtcp" port="514" ruleset="remote_tcp" RateLimit.Interval="5" RateLimit.Burst="20000")
input(type="imtcp" port="6514" ruleset="remote_tls" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.AuthMode="anon" RateLimit.Interval="5" RateLimit.Burst="20000")

set $!transport = "LOCAL";
call store_central
RSYSLOG_CONF

cat > /etc/rsyslog.d/15-allowed-senders.conf << ALLOWED_EOF
# Managed by SentinelLog Central Syslog Portal
\$AllowedSender UDP, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ${SERVER_IP}
\$AllowedSender TCP, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ${SERVER_IP}
ALLOWED_EOF

rsyslogd -N1
systemctl restart rsyslog
setfacl -m u:www-data:r /var/log/central-syslog/ingest/stream.ndjson 2>/dev/null || true

# --- Phase 5: MariaDB & Redis Setup ---
echo "[5/11] Configuring MariaDB database (${DB_NAME}) and Redis..."
systemctl enable --now mariadb redis-server
mysql -u root << SQL
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

# --- Phase 6: Laravel Portal Installation & Application Overlay ---
echo "[6/11] Installing Laravel project in /var/www/syslog-portal..."
mkdir -p /var/www
if [ ! -f /var/www/syslog-portal/artisan ]; then
    rm -rf /var/www/syslog-portal
    COMPOSER_ALLOW_SUPERUSER=1 /usr/local/bin/composer create-project laravel/laravel /var/www/syslog-portal --prefer-dist --no-interaction
fi

cd /var/www/syslog-portal
APP_KEY_VAL=$(grep '^APP_KEY=' .env | cut -d= -f2-)
if [ -z "${APP_KEY_VAL}" ]; then
    php artisan key:generate --force
    APP_KEY_VAL=$(grep '^APP_KEY=' .env | cut -d= -f2-)
fi

cat > .env << ENV_EOF
APP_NAME="SentinelLog Central Syslog"
APP_ENV=production
APP_KEY=${APP_KEY_VAL}
APP_DEBUG=false
APP_URL=https://${PORTAL_HOST}

APP_LOCALE=en
APP_FALLBACK_LOCALE=en
APP_FAKER_LOCALE=en_US
BCRYPT_ROUNDS=12

LOG_CHANNEL=stack
LOG_STACK=single
LOG_LEVEL=warning

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=${DB_NAME}
DB_USERNAME=${DB_USER}
DB_PASSWORD=${DB_PASS}

SYSLOG_INDEX_DB=/var/lib/central-syslog/index/syslog_hot.sqlite
SYSLOG_STREAM_FILE=/var/log/central-syslog/ingest/stream.ndjson
SYSLOG_HOSTS_DIR=/var/log/central-syslog/hosts
SYSLOG_ALLOWED_CONF=/etc/rsyslog.d/15-allowed-senders.conf

SESSION_DRIVER=database
SESSION_LIFETIME=120
SESSION_ENCRYPT=true
SESSION_PATH=/
SESSION_DOMAIN=null
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax

QUEUE_CONNECTION=redis
CACHE_STORE=redis
CACHE_PREFIX=syslog_portal_

REDIS_CLIENT=phpredis
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_MAILER=log
MAIL_FROM_ADDRESS="soc-alerts@${SERVER_IP}"
MAIL_FROM_NAME="SentinelLog SOC"
ENV_EOF

echo "Extracting SentinelLog portal application code..."
PAYLOAD_B64="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"
echo "${PAYLOAD_B64}" | base64 -d | tar -xzf - -C /var/www/syslog-portal
sed -i "s/'serverIp' => '103.72.109.7'/'serverIp' => '${SERVER_IP}'/g" /var/www/syslog-portal/app/Http/Controllers/SourceController.php
rm -f /var/www/syslog-portal/tests/Feature/ExampleTest.php

php artisan migrate --force
php artisan db:seed --force
php artisan syslog:ingest --once

chown -R www-data:www-data /var/www/syslog-portal
chmod -R 0750 /var/www/syslog-portal
chmod -R 0770 /var/www/syslog-portal/storage /var/www/syslog-portal/bootstrap/cache
chmod 0640 /var/www/syslog-portal/.env

# --- Phase 7: Helper Scripts & Sudoers ---
echo "[7/11] Installing rsyslog ACL sync and backup/restore scripts..."
cat > /opt/central-syslog/scripts/sync-allowed-senders.sh << 'SYNC_EOF'
#!/usr/bin/env bash
set -euo pipefail
STAGED="/var/lib/central-syslog/allowed_senders.staged"
TARGET="/etc/rsyslog.d/15-allowed-senders.conf"
BACKUP="/var/lib/central-syslog/15-allowed-senders.conf.bak"
[ -f "$STAGED" ] || exit 1
cp -f "$TARGET" "$BACKUP" 2>/dev/null || true
install -o root -g root -m 0644 "$STAGED" "$TARGET"
if rsyslogd -N1 >/dev/null 2>&1; then
    systemctl reload-or-restart rsyslog
    exit 0
else
    [ -f "$BACKUP" ] && install -o root -g root -m 0644 "$BACKUP" "$TARGET"
    exit 2
fi
SYNC_EOF
chmod 0750 /opt/central-syslog/scripts/sync-allowed-senders.sh
chown root:www-data /opt/central-syslog/scripts/sync-allowed-senders.sh

cat > /etc/sudoers.d/central-syslog << 'SUDO_EOF'
www-data ALL=(root) NOPASSWD: /opt/central-syslog/scripts/sync-allowed-senders.sh
SUDO_EOF
chmod 0440 /etc/sudoers.d/central-syslog

cat > /opt/central-syslog/scripts/backup-restore.sh << 'BKP_EOF'
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
        [ -n "$ARCHIVE" ] && [ -f "$ARCHIVE" ] || { echo "Usage: $0 restore /path/to/backup.tar.gz"; exit 1; }
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
esac
BKP_EOF
chmod 0750 /opt/central-syslog/scripts/backup-restore.sh

# --- Phase 8: Nginx HTTPS Virtual Host & Optional Certbot SSL ---
echo "[8/11] Configuring Nginx HTTPS virtual host..."
cat > /etc/nginx/sites-available/syslog-portal << NGINX_EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name ${DOMAIN_NAME} ${SERVER_IP} ${SERVER_HOSTNAME} _;
    server_tokens off;
    location = /up { return 200 "OK\n"; add_header Content-Type text/plain; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name ${DOMAIN_NAME} ${SERVER_IP} ${SERVER_HOSTNAME} _;

    root /var/www/syslog-portal/public;
    index index.php;
    server_tokens off;
    client_max_body_size 10M;

    ssl_certificate     /etc/nginx/ssl/syslog-portal.crt;
    ssl_certificate_key /etc/nginx/ssl/syslog-portal.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
        fastcgi_param HTTPS on;
        include fastcgi_params;
    }

    location ~ /\.(?!well-known).* { deny all; }
    location ~* \.(sqlite|sqlite3|ndjson|log|bak|env|sql)\$ { deny all; }
}
NGINX_EOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/syslog-portal /etc/nginx/sites-enabled/syslog-portal
nginx -t
systemctl enable --now php8.3-fpm nginx
systemctl reload nginx

if [ "${ENABLE_CERTBOT}" = "true" ] && [ -n "${DOMAIN_NAME}" ]; then
    echo "Installing Certbot and requesting Let's Encrypt SSL certificate for ${DOMAIN_NAME}..."
    apt-get install -y -qq certbot python3-certbot-nginx
    certbot --nginx -d "${DOMAIN_NAME}" --non-interactive --agree-tos --register-unsafely-without-email || \
        echo "WARNING: Certbot issuance failed (verify DNS and inbound TCP port 80). Falling back to self-signed TLS."
    systemctl enable --now certbot.timer || true
fi

if [ -f "$0" ] && [ "$(realpath "$0" 2>/dev/null || echo "")" != "/opt/central-syslog/install-sentinellog.sh" ]; then
    cp -f "$0" /opt/central-syslog/install-sentinellog.sh 2>/dev/null || true
    chmod 0750 /opt/central-syslog/install-sentinellog.sh 2>/dev/null || true
fi

# --- Phase 9: Systemd Indexer Daemon, Cron & Logrotate ---
echo "[9/11] Configuring systemd syslog-indexer daemon, cron, and logrotate..."
cat > /etc/systemd/system/syslog-indexer.service << 'SVC_EOF'
[Unit]
Description=SentinelLog Central Syslog FTS5 Indexer & Alert Engine
After=network.target rsyslog.service mariadb.service redis-server.service
Wants=rsyslog.service

[Service]
Type=simple
User=www-data
Group=adm
WorkingDirectory=/var/www/syslog-portal
ExecStart=/usr/bin/php /var/www/syslog-portal/artisan syslog:ingest
Restart=always
RestartSec=2
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVC_EOF

cat > /etc/cron.d/syslog-portal << 'CRON_EOF'
* * * * * www-data cd /var/www/syslog-portal && /usr/bin/php artisan schedule:run >> /dev/null 2>&1
15 2 * * * root find /var/log/central-syslog/hosts -type f -name "*.log" -mtime +1 -exec gzip -9 {} + 2>/dev/null || true
30 2 * * * root find /var/log/central-syslog/hosts -type f -name "*.gz" -mtime +90 -delete 2>/dev/null || true
CRON_EOF
chmod 0644 /etc/cron.d/syslog-portal

cat > /etc/logrotate.d/central-syslog << 'LR_EOF'
/var/log/central-syslog/ingest/stream.ndjson {
    daily
    rotate 7
    size 100M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 syslog adm
    postrotate
        /usr/bin/setfacl -m u:www-data:r /var/log/central-syslog/ingest/stream.ndjson >/dev/null 2>&1 || true
    endscript
}

/var/log/central-syslog/hosts/*/*/*.log {
    daily
    rotate 90
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate || true
    endscript
}
LR_EOF

systemctl daemon-reload
systemctl enable --now syslog-indexer.service

# --- Phase 10: UFW Firewall Configuration ---
echo "[10/11] Configuring UFW firewall rules..."
ufw allow "${SSH_PORT}/tcp" comment 'SSH Management' >/dev/null
ufw allow 80/tcp comment 'SentinelLog HTTP Redirect' >/dev/null
ufw allow 443/tcp comment 'SentinelLog HTTPS Portal' >/dev/null
ufw allow 514/udp comment 'Central Syslog UDP' >/dev/null
ufw allow 514/tcp comment 'Central Syslog TCP' >/dev/null
ufw allow 6514/tcp comment 'Central Syslog TLS' >/dev/null
ufw --force enable >/dev/null
ufw reload >/dev/null

# --- Phase 11: Optional Wazuh SIEM Agent Integration ---
if [ "${WAZUH_ENABLE}" = "true" ] && [ -n "${WAZUH_MANAGER_IP}" ]; then
    echo "[11/11] Installing and connecting Wazuh Agent (${WAZUH_VERSION}) to Manager ${WAZUH_MANAGER_IP}..."
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null || true
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    WAZUH_MANAGER="${WAZUH_MANAGER_IP}" WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" apt-get install -y "wazuh-agent=${WAZUH_VERSION}" || \
        WAZUH_MANAGER="${WAZUH_MANAGER_IP}" WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" apt-get install -y wazuh-agent
    apt-mark hold wazuh-agent || true

    if ! grep -q "stream.ndjson" /var/ossec/etc/ossec.conf; then
        cat >> /var/ossec/etc/ossec.conf << 'WAZUH_EOF'

<!-- SentinelLog Centralized Syslog & Portal Audit Integration -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/central-syslog/ingest/stream.ndjson</location>
    <label key="@source">central_syslog_stream</label>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/central-syslog/hosts/*/*/*.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/central-syslog/portal-audit.json</location>
    <label key="@source">sentinellog_portal_audit</label>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>
</ossec_config>
WAZUH_EOF
    fi
    systemctl daemon-reload
    systemctl enable --now wazuh-agent
    systemctl restart wazuh-agent
fi

echo "=================================================================="
echo " SentinelLog Deployment Complete!"
echo " Web Portal URL:    https://${PORTAL_HOST}"
echo " Syslog Listeners:  UDP 514 | TCP 514 | TLS 6514"
echo " Super Admin Login: admin@syslog.local  / Admin@Syslog2026!"
echo " Ops Admin Login:   ops@syslog.local    / Ops@Syslog2026!"
echo " Analyst Login:     analyst@syslog.local / Analyst@Syslog2026!"
echo " Read-Only Login:   viewer@syslog.local / Viewer@Syslog2026!"
echo "=================================================================="
