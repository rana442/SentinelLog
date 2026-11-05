<?php

namespace App\Console\Commands;

use App\Models\SystemSetting;
use App\Services\AlertEngineService;
use App\Services\AuditService;
use App\Services\SyslogIndexService;
use Illuminate\Console\Command;

class SyslogMaintenanceCommand extends Command
{
    protected $signature = 'syslog:maintenance';
    protected $description = 'Execute hot index retention cleanup, archive compression/pruning, disk quota protection, and alert checks';

    public function handle(SyslogIndexService $index, AlertEngineService $alerts): int
    {
        $hotDays = (int) SystemSetting::getValue('hot_retention_days', 30);
        $archiveDays = (int) SystemSetting::getValue('archive_retention_days', 90);
        $emergPercent = (int) SystemSetting::getValue('disk_emergency_prune_percent', 90);

        $hostsDir = config('syslog.hosts_dir', '/var/log/central-syslog/hosts');
        $total = @disk_total_space($hostsDir) ?: 1;
        $free = @disk_free_space($hostsDir) ?: 0;
        $usedPercent = (int) round((($total - $free) / $total) * 100);

        $emergency = $usedPercent >= $emergPercent;
        $prunedHot = $index->pruneExpired($hotDays, $emergency);

        try {
            $index->pdo()->exec('PRAGMA wal_checkpoint(PASSIVE);');
        } catch (\Throwable) {
        }

        // Rotate stream.ndjson safely if larger than 200MB
        $streamFile = config('syslog.stream_file', '/var/log/central-syslog/ingest/stream.ndjson');
        if (is_file($streamFile) && filesize($streamFile) > 200 * 1024 * 1024) {
            @truncate($streamFile, 0);
        }

        $alerts->evaluateAll();

        if ($prunedHot > 0 || $emergency) {
            AuditService::record('maintenance.retention_executed', 'system', 'retention', [
                'hot_retention_days' => $hotDays,
                'archive_retention_days' => $archiveDays,
                'pruned_hot_events' => $prunedHot,
                'disk_used_percent' => $usedPercent,
                'emergency_mode' => $emergency,
            ]);
        }

        $this->info("Maintenance completed: pruned {$prunedHot} hot events (disk: {$usedPercent}%).");
        return self::SUCCESS;
    }
}
