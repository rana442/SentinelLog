<?php

namespace App\Console\Commands;

use App\Models\LogSource;
use App\Services\AlertEngineService;
use App\Services\SyslogIndexService;
use Illuminate\Console\Command;
use PDO;

class SyslogIngestCommand extends Command
{
    protected $signature = 'syslog:ingest {--once : Process current backlog once and exit} {--max-lines=2000 : Max lines per batch}';
    protected $description = 'Ingest structured JSON syslog lines from rsyslog spool into the FTS5 search index and update source telemetry';

    public function handle(SyslogIndexService $index, AlertEngineService $alerts): int
    {
        $once = (bool) $this->option('once');
        $maxLines = max(100, (int) $this->option('max-lines'));
        $streamFile = config('syslog.stream_file', '/var/log/central-syslog/ingest/stream.ndjson');

        $lastAlertEval = 0;
        $lastCounterSync = 0;

        do {
            $processed = $this->processBatch($index, $streamFile, $maxLines);

            $now = time();
            if ($processed > 0 || ($now - $lastCounterSync) >= 30) {
                $this->refreshSourceCounters($index);
                $lastCounterSync = $now;
            }

            if ($processed > 0 || ($now - $lastAlertEval) >= 20) {
                try {
                    $alerts->evaluateAll();
                } catch (\Throwable $e) {
                    $this->warn('Alert evaluation warning: ' . $e->getMessage());
                }
                $lastAlertEval = $now;
            }

            if ($once) {
                break;
            }

            if ($processed === 0) {
                usleep(500000); // 0.5s idle sleep
            }
        } while (true);

        return self::SUCCESS;
    }

    protected function processBatch(SyslogIndexService $index, string $streamFile, int $maxLines): int
    {
        clearstatcache(true, $streamFile);
        if (!is_file($streamFile) || !is_readable($streamFile)) {
            return 0;
        }

        $stat = @stat($streamFile);
        if (!$stat) {
            return 0;
        }

        $inode = (int) $stat['ino'];
        $fileSize = (int) $stat['size'];

        $pdo = $index->pdo();
        $stateStmt = $pdo->prepare('SELECT inode, byte_offset FROM ingest_state WHERE stream_file = :sf');
        $stateStmt->execute([':sf' => $streamFile]);
        $state = $stateStmt->fetch();

        $offset = 0;
        if ($state) {
            if ((int) $state['inode'] === $inode && (int) $state['byte_offset'] <= $fileSize) {
                $offset = (int) $state['byte_offset'];
            }
        }

        if ($fileSize <= $offset) {
            return 0;
        }

        $fh = @fopen($streamFile, 'rb');
        if (!$fh) {
            return 0;
        }

        fseek($fh, $offset);
        $batch = [];
        $linesRead = 0;
        while ($linesRead < $maxLines && ($line = fgets($fh)) !== false) {
            // Only process complete newline-terminated lines
            if (!str_ends_with($line, "\n")) {
                break;
            }
            $offset = ftell($fh);
            $linesRead++;
            $trimmed = trim($line);
            if ($trimmed === '') {
                continue;
            }
            $decoded = json_decode($trimmed, true);
            if (is_array($decoded)) {
                $batch[] = $decoded;
            }
        }
        fclose($fh);

        if (!empty($batch)) {
            $inserted = $index->insertBatch($batch);
            $this->updateSourceHeartbeats($inserted);
        }

        $upsertStmt = $pdo->prepare(<<<'SQL'
INSERT INTO ingest_state (stream_file, inode, byte_offset, updated_at)
VALUES (:sf, :ino, :off, :ts)
ON CONFLICT(stream_file) DO UPDATE SET inode = excluded.inode, byte_offset = excluded.byte_offset, updated_at = excluded.updated_at
SQL);
        $upsertStmt->execute([
            ':sf' => $streamFile,
            ':ino' => $inode,
            ':off' => $offset,
            ':ts' => now()->utc()->toIso8601String(),
        ]);

        return count($batch);
    }

    protected function updateSourceHeartbeats(array $inserted): void
    {
        $byIp = [];
        foreach ($inserted as $ev) {
            $ip = $ev['source_ip'];
            if (!isset($byIp[$ip])) {
                $byIp[$ip] = [
                    'hostname' => $ev['hostname'],
                    'ip_address' => $ip,
                    'protocol' => $ev['protocol'],
                    'count' => 0,
                    'last_seen_at' => $ev['received_at'],
                ];
            }
            $byIp[$ip]['count']++;
            $byIp[$ip]['protocol'] = $ev['protocol'];
            if ($ev['received_at'] >= $byIp[$ip]['last_seen_at']) {
                $byIp[$ip]['last_seen_at'] = $ev['received_at'];
                if ($ev['hostname'] !== 'unknown') {
                    $byIp[$ip]['hostname'] = $ev['hostname'];
                }
            }
        }

        foreach ($byIp as $ip => $info) {
            $source = LogSource::where('ip_address', $ip)->first();
            if ($source) {
                $source->update([
                    'hostname' => $info['hostname'] ?: $source->hostname,
                    'last_seen_at' => $info['last_seen_at'],
                    'last_protocol' => $info['protocol'],
                    'total_events' => $source->total_events + $info['count'],
                ]);
            } else {
                LogSource::create([
                    'name' => strtoupper($info['hostname']) . " ({$ip})",
                    'hostname' => $info['hostname'],
                    'ip_address' => $ip,
                    'os_type' => 'Linux / Auto-Discovered',
                    'environment' => 'Production',
                    'location' => 'Auto-Discovered',
                    'owner' => 'SOC Operations',
                    'description' => 'Automatically registered upon receiving authorized syslog traffic.',
                    'is_enabled' => true,
                    'heartbeat_threshold_minutes' => 15,
                    'last_seen_at' => $info['last_seen_at'],
                    'last_protocol' => $info['protocol'],
                    'total_events' => $info['count'],
                ]);
            }
        }
    }

    protected function refreshSourceCounters(SyslogIndexService $index): void
    {
        $pdo = $index->pdo();
        $last5m = now()->utc()->subMinutes(5)->format('Y-m-d H:i:s');
        $last24h = now()->utc()->subHours(24)->format('Y-m-d H:i:s');

        $counts5m = $pdo->query("SELECT source_ip, COUNT(*) as cnt FROM syslog_events WHERE received_at >= '{$last5m}' GROUP BY source_ip")->fetchAll(PDO::FETCH_KEY_PAIR);
        $counts24h = $pdo->query("SELECT source_ip, COUNT(*) as cnt FROM syslog_events WHERE received_at >= '{$last24h}' GROUP BY source_ip")->fetchAll(PDO::FETCH_KEY_PAIR);

        foreach (LogSource::all() as $src) {
            $c5 = (int) ($counts5m[$src->ip_address] ?? 0);
            $c24 = (int) ($counts24h[$src->ip_address] ?? 0);
            if ($src->events_5m !== $c5 || $src->events_24h !== $c24) {
                $src->update([
                    'events_5m' => $c5,
                    'events_24h' => $c24,
                ]);
            }
        }
    }
}
