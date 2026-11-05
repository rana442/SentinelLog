# SentinelLog — Centralized Syslog Server & SOC Web Portal

**SentinelLog** is a production-ready, high-throughput Centralized Syslog Server, Real-Time Full-Text Search (SQLite FTS5) Indexer, Alert Engine, and Role-Based SOC Web Portal built with **Laravel 12**, **rsyslog**, **MariaDB**, **Redis**, **Nginx**, and optional **Wazuh SIEM** integration.

---

## Key Features

- **Multi-Transport Syslog Ingestion (`rsyslog`):**
  - **UDP `514`**, **TCP `514`**, and **TLS `6514`** (RFC 3164 & RFC 5424 compliant)
  - Automatic per-host daily log archiving (`/var/log/central-syslog/hosts/<sender-ip>/<YYYY-MM-DD>/<program>.log`)
  - Structured NDJSON real-time ingest stream (`/var/log/central-syslog/ingest/stream.ndjson`)
- **High-Speed Hot Search & Indexing (`syslog:ingest` daemon):**
  - Real-time indexing into **SQLite FTS5** (`/var/lib/central-syslog/index/syslog_hot.sqlite`) with WAL mode for sub-second full-text search across millions of syslog events
  - Automatic sender discovery, message counters, and health tracking (`Online` / `Stale` / `Silence`)
- **SOC Web Portal (Laravel 12 + Tailwind Dark SOC UI):**
  - **Executive Dashboard:** Total events, 24h volume, EPS (Events Per Second), severity breakdown (Emergency/Alert/Critical/Error/Warning/Notice/Info/Debug), top noisy hosts, and 24h timeline chart
  - **Live Tail (`/logs/live`):** Real-time streaming log viewer with pause/resume, severity badges, and protocol/host filtering
  - **Log Explorer (`/logs`):** Full-text FTS5 query search, date-range & severity filters, event detail modal (raw syslog + structured JSON), and **1-click CSV export**
  - **Sender Inventory & ACLs (`/senders`):** Manage allowed CIDR/IP subnets, synchronize directly to `/etc/rsyslog.d/15-allowed-senders.conf` with syntax validation (`rsyslogd -N1`), and monitor host silence thresholds
  - **Real-Time Alert Rules (`/alerts`):** Create threshold-based detection rules (keyword/program/severity match within sliding time windows) with webhook/email notification support
  - **Compliance Audit Trail (`/audit`):** Immutable portal activity log mirrored to `/var/log/central-syslog/portal-audit.json`
- **Role-Based Access Control (RBAC):**
  - `super_admin` — Full system, user, ACL, retention, and alert management
  - `ops_admin` — Sender ACLs, alert rules, and log operations
  - `soc_analyst` — Log search, live tail, alert acknowledgment, and CSV export
  - `auditor` — Read-only access to logs, dashboards, and audit trails
- **Automated SSL & Hardening:**
  - Built-in self-signed SAN TLS certificates + automated **Let's Encrypt (`certbot`)** provisioning and `systemd` auto-renewal (`certbot.timer`)
  - UFW firewall automation, kernel network buffer tuning (`sysctl`), `logrotate`, and automated cold archive cleanup

---

## System Requirements

| Resource | Minimum | Recommended (Production) |
| :--- | :--- | :--- |
| **OS** | Ubuntu Server 24.04 LTS (Noble Numbat) | Ubuntu Server 24.04 LTS (HWE Kernel) |
| **CPU** | 2 vCPU | 4+ vCPU |
| **RAM** | 4 GB | 8+ GB |
| **Disk** | 40 GB SSD | 100+ GB NVMe SSD (`/var/log` & `/var/lib`) |
| **Privileges** | `root` or `sudo` access | `root` or `sudo` access |

### Network Ports

| Port | Protocol | Service / Purpose |
| :--- | :--- | :--- |
| `80` | TCP | Nginx HTTP Redirect & Let's Encrypt ACME HTTP-01 Challenge |
| `443` | TCP | SentinelLog HTTPS Web Portal (TLS 1.2 / 1.3 + HTTP/2) |
| `514` | UDP / TCP | Standard Syslog Ingestion |
| `6514` | TCP | Encrypted Syslog over TLS Ingestion |
| `22` (or custom) | TCP | SSH Management (auto-detected by installer & preserved in UFW) |

---

## Quick Start — Automated 1-Command Installation

Clone this repository on a fresh **Ubuntu 24.04 LTS** server and run the standalone installer script [`install-sentinellog.sh`](install-sentinellog.sh).

### 1. Clone the Repository
```bash
git clone https://github.com/rana442/SentinelLog.git
cd SentinelLog
chmod +x install-sentinellog.sh
```

### 2. Run the Automated Installer

#### Option A: Standard Installation (Access via Server IP + Self-Signed TLS)
```bash
sudo bash install-sentinellog.sh
```

#### Option B: Production Domain + Automatic Let's Encrypt SSL (Recommended)
Ensure your domain's DNS `A` record points to your server's public IP and inbound TCP ports `80` and `443` are open on your firewall/router:
```bash
DOMAIN_NAME="syslog.yourdomain.com" \
ENABLE_CERTBOT="true" \
WAZUH_ENABLE="false" \
sudo -E bash install-sentinellog.sh
```

#### Option C: Custom Environment Overrides (With Wazuh SIEM Agent)
```bash
DOMAIN_NAME="syslog.example.com" \
ENABLE_CERTBOT="true" \
SERVER_IP="203.0.113.10" \
DB_PASS="YourStrongDbPassword!2026" \
WAZUH_ENABLE="true" \
WAZUH_MANAGER_IP="203.0.113.5" \
sudo -E bash install-sentinellog.sh
```

> **Note:** A copy of the auto-installer and operational helper scripts is automatically installed in `/opt/central-syslog/` (`/opt/central-syslog/install-sentinellog.sh` and `/opt/central-syslog/scripts/`).

---

## Installer Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SERVER_IP` | Auto-detected primary IPv4 | IPv4 address bound to Nginx, rsyslog ACLs, and TLS SAN |
| `SERVER_HOSTNAME` | `$(hostname -s)` | Short hostname of the server |
| `DOMAIN_NAME` | *(empty)* | Optional FQDN (e.g. `syslog.example.com`) for Nginx & `APP_URL` |
| `ENABLE_CERTBOT` | `false` | Set to `true` (with `DOMAIN_NAME`) to issue Let's Encrypt SSL and enable auto-renewal |
| `SSH_PORT` | Auto-detected from `sshd` | SSH port automatically allowed in UFW |
| `DB_NAME` | `syslog_portal` | MariaDB database name |
| `DB_USER` | `syslog_app` | MariaDB application username |
| `DB_PASS` | `SyslogP0rtal_2026!Sec` | MariaDB application password |
| `WAZUH_ENABLE` | `false` | Install and configure Wazuh Agent to forward normalized logs |
| `WAZUH_MANAGER_IP` | *(empty, e.g. `203.0.113.5`)* | Wazuh Manager IP address (required when `WAZUH_ENABLE=true`) |
| `INSTALL_HWE_KERNEL` | `true` | Install Ubuntu 24.04 HWE kernel (`linux-generic-hwe-24.04`) |

---

## Default Portal Credentials

After installation completes, open `https://<DOMAIN_NAME>` or `https://<SERVER_IP>` in your browser:

| Role | Email | Default Password |
| :--- | :--- | :--- |
| **Super Admin** | `admin@syslog.local` | `Admin@Syslog2026!` |
| **Ops Admin** | `ops@syslog.local` | `Ops@Syslog2026!` |
| **SOC Analyst** | `analyst@syslog.local` | `Analyst@Syslog2026!` |
| **Auditor (Read-Only)** | `viewer@syslog.local` | `Viewer@Syslog2026!` |

> **Security Recommendation:** Log in as `admin@syslog.local` immediately after deployment and rotate the default passwords under **Users & RBAC (`/users`)**.

---

## Enabling or Updating Let's Encrypt SSL Later

If you initially installed SentinelLog with an IP address and later point a domain (e.g., `syslog.yourdomain.com`) to the server:

1. Ensure inbound TCP port `80` and `443` are permitted on both UFW and your edge router/firewall.
2. Update `server_name` in `/etc/nginx/sites-available/syslog-portal` to include your domain and reload Nginx:
   ```bash
   sudo sed -i 's/server_name /server_name syslog.yourdomain.com /' /etc/nginx/sites-available/syslog-portal
   sudo nginx -t && sudo systemctl reload nginx
   ```
3. Install Certbot and issue the certificate:
   ```bash
   sudo apt-get update && sudo apt-get install -y certbot python3-certbot-nginx
   sudo certbot --nginx -d syslog.yourdomain.com --non-interactive --agree-tos --register-unsafely-without-email
   ```
4. Update `APP_URL` in `/var/www/syslog-portal/.env` and clear the cache:
   ```bash
   sudo sed -i 's|^APP_URL=.*|APP_URL=https://syslog.yourdomain.com|' /var/www/syslog-portal/.env
   sudo su -s /bin/bash www-data -c "cd /var/www/syslog-portal && php artisan config:clear"
   ```
5. Verify automatic renewal:
   ```bash
   sudo systemctl status certbot.timer
   sudo certbot renew --dry-run
   ```

---

## Sending Logs from Client Devices & Servers

Before sending logs from a new network segment, ensure the client's IP or subnet is permitted under **Sender Inventory (`/senders`)** in the Web Portal (by default, RFC1918 private networks `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and the server's own IP are allowed).

### Linux (`rsyslog` Client)
Create `/etc/rsyslog.d/90-sentinellog.conf` on the client machine:
```conf
# Forward all logs over TCP port 514 to SentinelLog
*.* @@<SENTINELLOG_SERVER_IP>:514
```
Restart rsyslog on the client:
```bash
sudo systemctl restart rsyslog
logger -t test-client "Hello SentinelLog from $(hostname)"
```

### Cisco / MikroTik / FortiGate / Network Appliances
- **Syslog Server IP:** `<SENTINELLOG_SERVER_IP>`
- **Port:** `514` (UDP or TCP) or `6514` (TLS)
- **Format:** RFC 5424 or BSD Syslog (RFC 3164)

---

## Directory Layout & Architecture

```text
/var/www/syslog-portal/                   # Laravel 12 SOC Web Portal
/opt/central-syslog/
├── install-sentinellog.sh                # Standalone Automated Installer
└── scripts/
    ├── sync-allowed-senders.sh           # Validates & applies rsyslog AllowedSender ACLs
    └── backup-restore.sh                 # Full backup/restore utility (MariaDB + SQLite + rsyslog + .env)
/var/log/central-syslog/
├── ingest/stream.ndjson                  # Live normalized NDJSON stream written by rsyslog
├── hosts/<sender-ip>/<YYYY-MM-DD>/*.log  # Per-host daily raw log archives (90-day retention)
└── portal-audit.json                     # Portal compliance audit log
/var/lib/central-syslog/
├── index/syslog_hot.sqlite               # SQLite FTS5 hot search database
└── backups/                              # Encrypted/restricted backup archives
```

---

## Operations, Backup & Troubleshooting

### Service Health Checks
```bash
sudo systemctl status rsyslog syslog-indexer nginx php8.3-fpm mariadb redis-server
```

### Backup & Restore
Create a full backup archive in `/var/lib/central-syslog/backups/`:
```bash
sudo /opt/central-syslog/scripts/backup-restore.sh backup
```
Restore from an archive:
```bash
sudo /opt/central-syslog/scripts/backup-restore.sh restore /var/lib/central-syslog/backups/sentinellog-backup-YYYYMMDD-HHMMSS.tar.gz
```

### Test Local Log Ingestion
```bash
logger -n 127.0.0.1 -P 514 -t sentinellog-test "Test message from localhost"
tail -n 5 /var/log/central-syslog/ingest/stream.ndjson
```

---

## License

MIT License.
