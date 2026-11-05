<?php

namespace App\Services;

use Carbon\Carbon;
use PDO;

class SyslogIndexService
{
    protected ?PDO $pdo = null;
    protected string $dbPath;

    public function __construct(?string $dbPath = null)
    {
        $this->dbPath = $dbPath ?? config('syslog.index_db', '/var/lib/central-syslog/index/syslog_hot.sqlite');
    }

    public function pdo(): PDO
    {
        if ($this->pdo !== null) {
            return $this->pdo;
        }

        $dir = dirname($this->dbPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }

        $isNewDb = !is_file($this->dbPath) || @filesize($this->dbPath) < 32768;

        $this->pdo = new PDO('sqlite:' . $this->dbPath, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_TIMEOUT => 10,
        ]);

        $this->pdo->exec('PRAGMA journal_mode = WAL;');
        $this->pdo->exec('PRAGMA synchronous = NORMAL;');
        $this->pdo->exec('PRAGMA temp_store = MEMORY;');
        $this->pdo->exec('PRAGMA busy_timeout = 10000;');

        if ($isNewDb) {
            $this->ensureSchema();
        }

        return $this->pdo;
    }

    public function ensureSchema(): void
    {
        $this->pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS syslog_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    reported_at TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    hostname TEXT NOT NULL,
    facility TEXT NOT NULL,
    facility_num INTEGER NOT NULL DEFAULT 1,
    severity TEXT NOT NULL,
    severity_num INTEGER NOT NULL DEFAULT 6,
    app_name TEXT NOT NULL,
    proc_id TEXT,
    msg_id TEXT,
    protocol TEXT NOT NULL DEFAULT 'UDP',
    event_category TEXT NOT NULL DEFAULT 'general',
    message TEXT NOT NULL,
    raw_message TEXT NOT NULL,
    archive_file TEXT NOT NULL,
    is_pinned INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_syslog_received ON syslog_events (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_sev_rec ON syslog_events (severity_num, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_host_rec ON syslog_events (hostname, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_ip_rec ON syslog_events (source_ip, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_fac_rec ON syslog_events (facility, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_app_rec ON syslog_events (app_name, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_cat_rec ON syslog_events (event_category, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_proto_rec ON syslog_events (protocol, received_at DESC);

CREATE VIRTUAL TABLE IF NOT EXISTS syslog_events_fts USING fts5(
    hostname,
    source_ip,
    app_name,
    message,
    raw_message,
    content='syslog_events',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);

CREATE TRIGGER IF NOT EXISTS trg_syslog_events_ai AFTER INSERT ON syslog_events BEGIN
    INSERT INTO syslog_events_fts(rowid, hostname, source_ip, app_name, message, raw_message)
    VALUES (new.id, new.hostname, new.source_ip, new.app_name, new.message, new.raw_message);
END;

CREATE TRIGGER IF NOT EXISTS trg_syslog_events_ad AFTER DELETE ON syslog_events BEGIN
    INSERT INTO syslog_events_fts(syslog_events_fts, rowid, hostname, source_ip, app_name, message, raw_message)
    VALUES ('delete', old.id, old.hostname, old.source_ip, old.app_name, old.message, old.raw_message);
END;

CREATE TABLE IF NOT EXISTS ingest_state (
    stream_file TEXT PRIMARY KEY,
    inode INTEGER NOT NULL DEFAULT 0,
    byte_offset INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
SQL);
    }

    /**
     * Strip terminal escape sequences and control characters to prevent terminal/browser log injection.
     */
    public static function sanitizeLogText(string $input): string
    {
        // Strip ANSI CSI escape sequences
        $clean = preg_replace('/\x1B\[[0-?]*[ -\/]*[@-~]/u', '', $input) ?? $input;
        // Replace control chars (except tab) with safe visible hex or space
        $clean = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', ' ', $clean) ?? $clean;
        return trim($clean);
    }

    public static function sanitizeHostname(string $hostname): string
    {
        $clean = preg_replace('/[^a-zA-Z0-9._\-]/', '_', trim($hostname)) ?? 'unknown';
        return substr($clean ?: 'unknown', 0, 190);
    }

    public static function sanitizeIp(string $ip): string
    {
        $trimmed = trim($ip);
        if (filter_var($trimmed, FILTER_VALIDATE_IP)) {
            return $trimmed;
        }
        return '0.0.0.0';
    }

    public static function classifyEvent(string $facility, string $appName, string $message, int $severityNum): string
    {
        $msgLower = strtolower($message);
        $appLower = strtolower($appName);

        if (str_contains($msgLower, 'ufw block') || str_contains($msgLower, 'iptables') || str_contains($msgLower, 'nftables') || str_contains($msgLower, 'firewall') || str_contains($appLower, 'fw')) {
            return 'firewall';
        }
        if (str_contains($appLower, 'sudo') || str_contains($msgLower, 'sudo:')) {
            return 'sudo';
        }
        if (
            str_contains($msgLower, 'failed password') ||
            str_contains($msgLower, 'authentication failure') ||
            str_contains($msgLower, 'invalid user') ||
            str_contains($msgLower, 'auth failed') ||
            str_contains($msgLower, 'access denied')
        ) {
            return 'auth_failure';
        }
        if (str_contains($appLower, 'sshd') && (str_contains($msgLower, 'accepted ') || str_contains($msgLower, 'session opened') || str_contains($msgLower, 'disconnected'))) {
            return 'ssh_auth';
        }
        if ($facility === 'kern' || $appLower === 'kernel') {
            return 'kernel';
        }
        if (
            str_contains($msgLower, 'failed with result') ||
            str_contains($msgLower, 'service failed') ||
            str_contains($msgLower, 'segfault') ||
            str_contains($msgLower, 'out of memory') ||
            str_contains($msgLower, 'killed process') ||
            ($facility === 'daemon' && $severityNum <= 3)
        ) {
            return 'service_failure';
        }

        return 'general';
    }

    /**
     * Insert a batch of parsed syslog events inside a single transaction.
     */
    public function insertBatch(array $rawEvents): array
    {
        if (empty($rawEvents)) {
            return [];
        }

        $pdo = $this->pdo();
        $stmt = $pdo->prepare(<<<'SQL'
INSERT INTO syslog_events (
    received_at, reported_at, source_ip, hostname, facility, facility_num,
    severity, severity_num, app_name, proc_id, msg_id, protocol,
    event_category, message, raw_message, archive_file, is_pinned
) VALUES (
    :received_at, :reported_at, :source_ip, :hostname, :facility, :facility_num,
    :severity, :severity_num, :app_name, :proc_id, :msg_id, :protocol,
    :event_category, :message, :raw_message, :archive_file, 0
)
SQL);

        $normalized = [];
        $pdo->beginTransaction();
        try {
            foreach ($rawEvents as $ev) {
                $receivedAt = $this->normalizeTimestamp($ev['received_at'] ?? null);
                $reportedAt = $this->normalizeTimestamp($ev['reported_at'] ?? $receivedAt);
                $sourceIp = self::sanitizeIp((string) ($ev['source_ip'] ?? '127.0.0.1'));
                $hostname = self::sanitizeHostname((string) ($ev['hostname'] ?? 'unknown'));
                $facility = strtolower(preg_replace('/[^a-zA-Z0-9_\-]/', '', (string) ($ev['facility'] ?? 'user')) ?: 'user');
                $facilityNum = max(0, min(23, (int) ($ev['facility_num'] ?? 1)));
                $severityNum = max(0, min(7, (int) ($ev['severity_num'] ?? 6)));
                $severityMap = [0 => 'emerg', 1 => 'alert', 2 => 'crit', 3 => 'err', 4 => 'warning', 5 => 'notice', 6 => 'info', 7 => 'debug'];
                $severity = $severityMap[$severityNum] ?? 'info';
                $appName = substr(preg_replace('/[^a-zA-Z0-9._\-\/]/', '', (string) ($ev['app_name'] ?? '-')) ?: '-', 0, 96);
                $procId = substr(self::sanitizeLogText((string) ($ev['proc_id'] ?? '-')), 0, 32);
                $msgId = substr(self::sanitizeLogText((string) ($ev['msg_id'] ?? '-')), 0, 64);
                $protocol = strtoupper((string) ($ev['protocol'] ?? 'UDP'));
                if (!in_array($protocol, ['UDP', 'TCP', 'TLS', 'LOCAL'], true)) {
                    $protocol = 'UDP';
                }

                $message = self::sanitizeLogText((string) ($ev['message'] ?? ''));
                $rawMessage = self::sanitizeLogText((string) ($ev['raw_message'] ?? $message));
                $category = self::classifyEvent($facility, $appName, $message, $severityNum);
                $datePart = substr($receivedAt, 0, 10);
                $archiveFile = sprintf('/var/log/central-syslog/hosts/%s_%s/%s/%s.log', $sourceIp, $hostname, $datePart, $facility);

                $row = [
                    'received_at' => $receivedAt,
                    'reported_at' => $reportedAt,
                    'source_ip' => $sourceIp,
                    'hostname' => $hostname,
                    'facility' => $facility,
                    'facility_num' => $facilityNum,
                    'severity' => $severity,
                    'severity_num' => $severityNum,
                    'app_name' => $appName,
                    'proc_id' => $procId,
                    'msg_id' => $msgId,
                    'protocol' => $protocol,
                    'event_category' => $category,
                    'message' => $message,
                    'raw_message' => $rawMessage,
                    'archive_file' => $archiveFile,
                ];

                $stmt->execute($row);
                $row['id'] = (int) $pdo->lastInsertId();
                $normalized[] = $row;
            }
            $pdo->commit();
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }

        return $normalized;
    }

    protected function normalizeTimestamp(?string $ts): string
    {
        try {
            return $ts ? Carbon::parse($ts)->utc()->format('Y-m-d H:i:s') : now()->utc()->format('Y-m-d H:i:s');
        } catch (\Throwable) {
            return now()->utc()->format('Y-m-d H:i:s');
        }
    }

    /**
     * Build safe FTS5 query string from user search input (prevents syntax injection and expensive wildcard DoS).
     */
    public static function buildSafeFtsQuery(string $rawQuery): ?string
    {
        $cleaned = preg_replace('/[^\p{L}\p{N}._\-:\/]/u', ' ', trim($rawQuery)) ?? '';
        $tokens = array_values(array_filter(explode(' ', $cleaned), fn($t) => strlen($t) >= 2));
        if (empty($tokens)) {
            return null;
        }
        $tokens = array_slice($tokens, 0, 8);
        return implode(' AND ', array_map(fn($t) => '"' . str_replace('"', '', $t) . '"*', $tokens));
    }

    public function search(array $filters = [], int $perPage = 50, int $page = 1, string $sortDir = 'DESC'): array
    {
        $pdo = $this->pdo();
        $perPage = max(10, min(250, $perPage));
        $page = max(1, $page);
        $offset = ($page - 1) * $perPage;
        $sortDir = strtoupper($sortDir) === 'ASC' ? 'ASC' : 'DESC';

        $where = ['1=1'];
        $params = [];

        if (!empty($filters['q'])) {
            $ftsQuery = self::buildSafeFtsQuery((string) $filters['q']);
            if ($ftsQuery !== null) {
                $where[] = 'e.id IN (SELECT rowid FROM syslog_events_fts WHERE syslog_events_fts MATCH :fts_q)';
                $params[':fts_q'] = $ftsQuery;
            }
        }

        if (!empty($filters['hostname'])) {
            $where[] = 'e.hostname = :hostname';
            $params[':hostname'] = trim((string) $filters['hostname']);
        }

        if (!empty($filters['source_ip'])) {
            $where[] = 'e.source_ip = :source_ip';
            $params[':source_ip'] = trim((string) $filters['source_ip']);
        }

        if (isset($filters['severity']) && $filters['severity'] !== '') {
            if (is_numeric($filters['severity'])) {
                $where[] = 'e.severity_num = :severity_num';
                $params[':severity_num'] = (int) $filters['severity'];
            } else {
                $where[] = 'e.severity = :severity_name';
                $params[':severity_name'] = strtolower(trim((string) $filters['severity']));
            }
        }

        if (isset($filters['max_severity']) && $filters['max_severity'] !== '') {
            $where[] = 'e.severity_num <= :max_sev';
            $params[':max_sev'] = (int) $filters['max_severity'];
        }

        if (!empty($filters['facility'])) {
            $where[] = 'e.facility = :facility';
            $params[':facility'] = strtolower(trim((string) $filters['facility']));
        }

        if (!empty($filters['app_name'])) {
            $where[] = 'e.app_name = :app_name';
            $params[':app_name'] = trim((string) $filters['app_name']);
        }

        if (!empty($filters['protocol'])) {
            $where[] = 'e.protocol = :protocol';
            $params[':protocol'] = strtoupper(trim((string) $filters['protocol']));
        }

        if (!empty($filters['quick_filter'])) {
            $qf = (string) $filters['quick_filter'];
            if (in_array($qf, ['auth_failure', 'ssh_auth', 'sudo', 'kernel', 'service_failure', 'firewall'], true)) {
                $where[] = 'e.event_category = :event_category';
                $params[':event_category'] = $qf;
            } elseif ($qf === 'pinned') {
                $where[] = 'e.is_pinned = 1';
            } elseif ($qf === 'critical_only') {
                $where[] = 'e.severity_num <= 2';
            }
        }

        if (!empty($filters['date_from'])) {
            try {
                $params[':date_from'] = Carbon::parse($filters['date_from'])->utc()->format('Y-m-d H:i:s');
                $where[] = 'e.received_at >= :date_from';
            } catch (\Throwable) {}
        }

        if (!empty($filters['date_to'])) {
            try {
                $params[':date_to'] = Carbon::parse($filters['date_to'])->utc()->format('Y-m-d H:i:s');
                $where[] = 'e.received_at <= :date_to';
            } catch (\Throwable) {}
        }

        $whereSql = implode(' AND ', $where);

        $countStmt = $pdo->prepare("SELECT COUNT(*) FROM syslog_events e WHERE {$whereSql}");
        $countStmt->execute($params);
        $total = (int) $countStmt->fetchColumn();

        $sql = "SELECT e.* FROM syslog_events e WHERE {$whereSql} ORDER BY e.received_at {$sortDir}, e.id {$sortDir} LIMIT :limit OFFSET :offset";
        $stmt = $pdo->prepare($sql);
        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }
        $stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $items = $stmt->fetchAll();

        return [
            'items' => $items,
            'total' => $total,
            'per_page' => $perPage,
            'current_page' => $page,
            'last_page' => max(1, (int) ceil($total / $perPage)),
        ];
    }

    public function findEvent(int $id): ?array
    {
        $stmt = $this->pdo()->prepare('SELECT * FROM syslog_events WHERE id = :id');
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function togglePin(int $id): ?array
    {
        $event = $this->findEvent($id);
        if (!$event) {
            return null;
        }
        $newVal = ((int) $event['is_pinned'] === 1) ? 0 : 1;
        $stmt = $this->pdo()->prepare('UPDATE syslog_events SET is_pinned = :val WHERE id = :id');
        $stmt->execute([':val' => $newVal, ':id' => $id]);
        $event['is_pinned'] = $newVal;
        return $event;
    }

    public function getFacetOptions(): array
    {
        $pdo = $this->pdo();
        $since = now()->utc()->subDays(7)->format('Y-m-d H:i:s');
        $hosts = $pdo->query("SELECT DISTINCT hostname FROM syslog_events WHERE received_at >= '{$since}' ORDER BY hostname LIMIT 100")->fetchAll(PDO::FETCH_COLUMN);
        $ips = $pdo->query("SELECT DISTINCT source_ip FROM syslog_events WHERE received_at >= '{$since}' ORDER BY source_ip LIMIT 100")->fetchAll(PDO::FETCH_COLUMN);
        $facilities = $pdo->query("SELECT DISTINCT facility FROM syslog_events WHERE received_at >= '{$since}' ORDER BY facility LIMIT 50")->fetchAll(PDO::FETCH_COLUMN);
        $apps = $pdo->query("SELECT DISTINCT app_name FROM syslog_events WHERE received_at >= '{$since}' AND app_name != '-' ORDER BY app_name LIMIT 100")->fetchAll(PDO::FETCH_COLUMN);

        return compact('hosts', 'ips', 'facilities', 'apps');
    }

    public function getRecentEvents(int $afterId = 0, int $limit = 40, array $filters = []): array
    {
        $pdo = $this->pdo();
        $limit = max(5, min(100, $limit));
        $where = ['id > :after_id'];
        $params = [':after_id' => $afterId];

        if (!empty($filters['hostname'])) {
            $where[] = 'hostname = :hostname';
            $params[':hostname'] = $filters['hostname'];
        }
        if (isset($filters['max_severity']) && $filters['max_severity'] !== '') {
            $where[] = 'severity_num <= :max_sev';
            $params[':max_sev'] = (int) $filters['max_severity'];
        }
        if (!empty($filters['protocol'])) {
            $where[] = 'protocol = :proto';
            $params[':proto'] = strtoupper($filters['protocol']);
        }

        $whereSql = implode(' AND ', $where);
        $stmt = $pdo->prepare("SELECT * FROM syslog_events WHERE {$whereSql} ORDER BY id DESC LIMIT :limit");
        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function getDashboardMetrics(): array
    {
        $pdo = $this->pdo();
        $nowUtc = now()->utc();
        $todayStart = $nowUtc->copy()->startOfDay()->format('Y-m-d H:i:s');
        $last5m = $nowUtc->copy()->subMinutes(5)->format('Y-m-d H:i:s');
        $last24h = $nowUtc->copy()->subHours(24)->format('Y-m-d H:i:s');
        $last7d = $nowUtc->copy()->subDays(7)->format('Y-m-d H:i:s');

        $totalToday = (int) $pdo->query("SELECT COUNT(*) FROM syslog_events WHERE received_at >= '{$todayStart}'")->fetchColumn();
        $eventsLast5m = (int) $pdo->query("SELECT COUNT(*) FROM syslog_events WHERE received_at >= '{$last5m}'")->fetchColumn();
        $epm = round($eventsLast5m / 5, 1);

        $sevCountsStmt = $pdo->query("SELECT severity_num, COUNT(*) as cnt FROM syslog_events WHERE received_at >= '{$last24h}' GROUP BY severity_num");
        $severityDistribution = array_fill(0, 8, 0);
        foreach ($sevCountsStmt->fetchAll() as $r) {
            $severityDistribution[(int) $r['severity_num']] = (int) $r['cnt'];
        }

        $warningAndErrorCount = $severityDistribution[3] + $severityDistribution[4];
        $criticalAndEmergencyCount = $severityDistribution[0] + $severityDistribution[1] + $severityDistribution[2];

        $topHosts = $pdo->query("SELECT hostname, source_ip, COUNT(*) as total FROM syslog_events WHERE received_at >= '{$last24h}' GROUP BY hostname, source_ip ORDER BY total DESC LIMIT 8")->fetchAll();
        $topApps = $pdo->query("SELECT app_name, COUNT(*) as total FROM syslog_events WHERE received_at >= '{$last24h}' AND app_name != '-' GROUP BY app_name ORDER BY total DESC LIMIT 8")->fetchAll();

        $hourlyRows = $pdo->query("SELECT substr(received_at, 1, 13) || ':00' as hour_bucket, COUNT(*) as total FROM syslog_events WHERE received_at >= '{$last24h}' GROUP BY hour_bucket ORDER BY hour_bucket ASC")->fetchAll();
        $dailyRows = $pdo->query("SELECT substr(received_at, 1, 10) as day_bucket, COUNT(*) as total FROM syslog_events WHERE received_at >= '{$last7d}' GROUP BY day_bucket ORDER BY day_bucket ASC")->fetchAll();

        $recentCritical = $pdo->query("SELECT * FROM syslog_events WHERE severity_num <= 2 AND received_at >= '{$last24h}' ORDER BY received_at DESC, id DESC LIMIT 10")->fetchAll();
        $recentAuthFailures = $pdo->query("SELECT * FROM syslog_events WHERE event_category = 'auth_failure' AND received_at >= '{$last24h}' ORDER BY received_at DESC, id DESC LIMIT 8")->fetchAll();
        $recentSshLogins = $pdo->query("SELECT * FROM syslog_events WHERE event_category IN ('ssh_auth', 'auth_failure') AND received_at >= '{$last24h}' AND app_name LIKE '%sshd%' ORDER BY received_at DESC, id DESC LIMIT 8")->fetchAll();
        $recentServiceErrors = $pdo->query("SELECT * FROM syslog_events WHERE event_category = 'service_failure' AND received_at >= '{$last24h}' ORDER BY received_at DESC, id DESC LIMIT 8")->fetchAll();

        return [
            'total_today' => $totalToday,
            'events_per_minute' => $epm,
            'warning_error_24h' => $warningAndErrorCount,
            'critical_emerg_24h' => $criticalAndEmergencyCount,
            'severity_distribution' => $severityDistribution,
            'top_hosts' => $topHosts,
            'top_apps' => $topApps,
            'hourly_trend' => $hourlyRows,
            'daily_trend' => $dailyRows,
            'recent_critical' => $recentCritical,
            'recent_auth_failures' => $recentAuthFailures,
            'recent_ssh_events' => $recentSshLogins,
            'recent_service_errors' => $recentServiceErrors,
        ];
    }

    /**
     * Prune unpinned hot logs older than $hotRetentionDays.
     * Never deletes logs where is_pinned = 1 (active investigation protection).
     */
    public function pruneExpired(int $hotRetentionDays = 30, bool $emergencyMode = false): int
    {
        $cutoff = now()->utc()->subDays(max(1, $hotRetentionDays))->format('Y-m-d H:i:s');
        $stmt = $this->pdo()->prepare('DELETE FROM syslog_events WHERE is_pinned = 0 AND received_at < :cutoff');
        $stmt->execute([':cutoff' => $cutoff]);
        $deleted = $stmt->rowCount();

        if ($emergencyMode && $deleted === 0) {
            // In emergency disk pressure (>90%), prune oldest 20% of unpinned logs while preserving pinned investigation logs
            $stmtEmerg = $this->pdo()->prepare(
                'DELETE FROM syslog_events WHERE id IN (SELECT id FROM syslog_events WHERE is_pinned = 0 ORDER BY received_at ASC LIMIT 50000)'
            );
            $stmtEmerg->execute();
            $deleted += $stmtEmerg->rowCount();
        }

        return $deleted;
    }
}
