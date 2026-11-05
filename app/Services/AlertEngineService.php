<?php

namespace App\Services;

use App\Models\AlertIncident;
use App\Models\AlertRule;
use App\Models\LogSource;
use App\Models\SystemSetting;
use App\Services\Notification\NotificationDispatcher;

class AlertEngineService
{
    public function __construct(
        protected SyslogIndexService $index,
        protected NotificationDispatcher $notifier
    ) {}

    /**
     * Evaluate all enabled alert rules against recent indexed events, source heartbeats, and disk usage.
     */
    public function evaluateAll(): int
    {
        $rules = AlertRule::where('is_enabled', true)->get();
        $triggeredCount = 0;

        foreach ($rules as $rule) {
            if ($this->isInCooldown($rule)) {
                continue;
            }

            $fired = match ($rule->rule_type) {
                'auth_failure' => $this->checkCategoryThreshold($rule, 'auth_failure', 'high', 'Repeated Authentication Failures Detected'),
                'ssh_bruteforce' => $this->checkSshBruteForce($rule),
                'critical_severity' => $this->checkCriticalMessages($rule),
                'service_failure' => $this->checkCategoryThreshold($rule, 'service_failure', 'high', 'Service Shutdown / Failure Burst'),
                'disk_usage' => $this->checkDiskUsage($rule),
                'volume_spike' => $this->checkVolumeSpike($rule),
                'silent_source' => $this->checkSilentSources($rule),
                'custom_pattern' => $this->checkCustomPattern($rule),
                default => false,
            };

            if ($fired) {
                $triggeredCount++;
            }
        }

        return $triggeredCount;
    }

    protected function isInCooldown(AlertRule $rule): bool
    {
        if (!$rule->last_triggered_at) {
            return false;
        }
        return $rule->last_triggered_at->diffInMinutes(now()) < max(1, (int) $rule->cooldown_minutes);
    }

    protected function checkCategoryThreshold(AlertRule $rule, string $category, string $severity, string $label): bool
    {
        $pdo = $this->index->pdo();
        $since = now()->utc()->subMinutes(max(1, (int) $rule->window_minutes))->format('Y-m-d H:i:s');
        $stmt = $pdo->prepare("
            SELECT hostname, source_ip, COUNT(*) as cnt, MAX(message) as sample_msg
            FROM syslog_events
            WHERE event_category = :cat AND received_at >= :since
            GROUP BY hostname, source_ip
            HAVING COUNT(*) >= CAST(:threshold AS INTEGER)
            ORDER BY cnt DESC
            LIMIT 1
        ");
        $stmt->execute([
            ':cat' => $category,
            ':since' => $since,
            ':threshold' => max(1, (int) $rule->threshold_count),
        ]);
        $match = $stmt->fetch();
        if (!$match) {
            return false;
        }

        return $this->triggerIncident(
            $rule,
            "{$rule->rule_type}:{$match['hostname']}:{$match['source_ip']}",
            $severity,
            "{$label} on {$match['hostname']}",
            sprintf(
                "Host %s (%s) generated %d '%s' events within %d minutes. Sample: %s",
                $match['hostname'],
                $match['source_ip'],
                (int) $match['cnt'],
                $category,
                $rule->window_minutes,
                substr((string) $match['sample_msg'], 0, 200)
            ),
            $match['hostname'],
            $match['source_ip'],
            (int) $match['cnt'],
            ['sample_message' => $match['sample_msg'], 'window_minutes' => $rule->window_minutes]
        );
    }

    protected function checkSshBruteForce(AlertRule $rule): bool
    {
        $pdo = $this->index->pdo();
        $since = now()->utc()->subMinutes(max(1, (int) $rule->window_minutes))->format('Y-m-d H:i:s');
        $stmt = $pdo->prepare("
            SELECT hostname, source_ip, COUNT(*) as cnt, MAX(message) as sample_msg
            FROM syslog_events
            WHERE event_category = 'auth_failure'
              AND (app_name LIKE '%sshd%' OR message LIKE '%ssh%' OR message LIKE '%Failed password%')
              AND received_at >= :since
            GROUP BY hostname, source_ip
            HAVING COUNT(*) >= CAST(:threshold AS INTEGER)
            ORDER BY cnt DESC
            LIMIT 1
        ");
        $stmt->execute([
            ':since' => $since,
            ':threshold' => max(1, (int) $rule->threshold_count),
        ]);
        $match = $stmt->fetch();
        if (!$match) {
            return false;
        }

        return $this->triggerIncident(
            $rule,
            "ssh_bruteforce:{$match['hostname']}:{$match['source_ip']}",
            'critical',
            "SSH Brute-Force Indicator on {$match['hostname']}",
            sprintf(
                "Detected %d SSH authentication failures on %s (%s) in the last %d minutes. Sample: %s",
                (int) $match['cnt'],
                $match['hostname'],
                $match['source_ip'],
                $rule->window_minutes,
                substr((string) $match['sample_msg'], 0, 200)
            ),
            $match['hostname'],
            $match['source_ip'],
            (int) $match['cnt'],
            ['sample_message' => $match['sample_msg']]
        );
    }

    protected function checkCriticalMessages(AlertRule $rule): bool
    {
        $pdo = $this->index->pdo();
        $since = now()->utc()->subMinutes(max(1, (int) $rule->window_minutes))->format('Y-m-d H:i:s');
        $maxSev = $rule->severity_threshold !== null ? (int) $rule->severity_threshold : 2;

        $stmt = $pdo->prepare("
            SELECT hostname, source_ip, COUNT(*) as cnt, MAX(message) as sample_msg
            FROM syslog_events
            WHERE severity_num <= CAST(:max_sev AS INTEGER) AND received_at >= :since
            GROUP BY hostname, source_ip
            HAVING COUNT(*) >= CAST(:threshold AS INTEGER)
            ORDER BY cnt DESC
            LIMIT 1
        ");
        $stmt->execute([
            ':max_sev' => $maxSev,
            ':since' => $since,
            ':threshold' => max(1, (int) $rule->threshold_count),
        ]);
        $match = $stmt->fetch();
        if (!$match) {
            return false;
        }

        return $this->triggerIncident(
            $rule,
            "crit_sev:{$match['hostname']}:{$match['source_ip']}",
            'critical',
            "Critical / Emergency Syslog Events from {$match['hostname']}",
            sprintf(
                "Received %d Critical/Alert/Emergency event(s) from %s (%s) in %d minutes. Latest: %s",
                (int) $match['cnt'],
                $match['hostname'],
                $match['source_ip'],
                $rule->window_minutes,
                substr((string) $match['sample_msg'], 0, 200)
            ),
            $match['hostname'],
            $match['source_ip'],
            (int) $match['cnt'],
            ['sample_message' => $match['sample_msg']]
        );
    }

    protected function checkDiskUsage(AlertRule $rule): bool
    {
        $path = config('syslog.hosts_dir', '/var/log/central-syslog/hosts');
        if (!is_dir($path)) {
            $path = '/';
        }
        $total = @disk_total_space($path) ?: 1;
        $free = @disk_free_space($path) ?: 0;
        $usedPercent = (int) round((($total - $free) / $total) * 100);
        $threshold = max(50, min(99, (int) ($rule->threshold_count ?: SystemSetting::getValue('disk_warning_percent', 75))));

        if ($usedPercent < $threshold) {
            return false;
        }

        $sev = $usedPercent >= (int) SystemSetting::getValue('disk_critical_percent', 85) ? 'critical' : 'warning';
        return $this->triggerIncident(
            $rule,
            "disk_usage:{$threshold}",
            $sev,
            "Log Storage Disk Usage at {$usedPercent}%",
            sprintf("Central syslog storage partition usage is %d%% (threshold: %d%%).", $usedPercent, $threshold),
            gethostname() ?: 'syslog',
            '127.0.0.1',
            $usedPercent,
            ['used_percent' => $usedPercent, 'threshold' => $threshold]
        );
    }

    protected function checkVolumeSpike(AlertRule $rule): bool
    {
        $pdo = $this->index->pdo();
        $since = now()->utc()->subMinutes(max(1, (int) $rule->window_minutes))->format('Y-m-d H:i:s');
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM syslog_events WHERE received_at >= :since");
        $stmt->execute([':since' => $since]);
        $count = (int) $stmt->fetchColumn();

        if ($count < max(10, (int) $rule->threshold_count)) {
            return false;
        }

        return $this->triggerIncident(
            $rule,
            "volume_spike",
            'warning',
            "Log Ingestion Volume Spike ({$count} events / {$rule->window_minutes}m)",
            sprintf("Total syslog volume reached %d events in the last %d minutes (threshold: %d).", $count, $rule->window_minutes, $rule->threshold_count),
            'all-sources',
            '0.0.0.0',
            $count,
            ['window_minutes' => $rule->window_minutes, 'count' => $count]
        );
    }

    protected function checkSilentSources(AlertRule $rule): bool
    {
        $sources = LogSource::where('is_enabled', true)->where('alert_on_silent', true)->whereNotNull('last_seen_at')->get();
        foreach ($sources as $source) {
            if ($source->healthStatus() === 'Offline') {
                return $this->triggerIncident(
                    $rule,
                    "silent_source:{$source->ip_address}",
                    'high',
                    "Registered Source Offline: {$source->hostname} ({$source->ip_address})",
                    sprintf(
                        "Registered source %s (%s) has not sent logs since %s (threshold: %d min).",
                        $source->hostname,
                        $source->ip_address,
                        $source->last_seen_at->toIso8601String(),
                        $source->heartbeat_threshold_minutes
                    ),
                    $source->hostname,
                    $source->ip_address,
                    1,
                    ['last_seen_at' => $source->last_seen_at->toIso8601String()]
                );
            }
        }
        return false;
    }

    protected function checkCustomPattern(AlertRule $rule): bool
    {
        if (empty($rule->pattern)) {
            return false;
        }

        $pdo = $this->index->pdo();
        $since = now()->utc()->subMinutes(max(1, (int) $rule->window_minutes))->format('Y-m-d H:i:s');
        $stmt = $pdo->prepare("
            SELECT hostname, source_ip, COUNT(*) as cnt, MAX(message) as sample_msg
            FROM syslog_events
            WHERE message LIKE :pat AND received_at >= :since
            GROUP BY hostname, source_ip
            HAVING COUNT(*) >= CAST(:threshold AS INTEGER)
            ORDER BY cnt DESC
            LIMIT 1
        ");
        $stmt->execute([
            ':pat' => '%' . $rule->pattern . '%',
            ':since' => $since,
            ':threshold' => max(1, (int) $rule->threshold_count),
        ]);
        $match = $stmt->fetch();
        if (!$match) {
            return false;
        }

        return $this->triggerIncident(
            $rule,
            "custom:{$rule->id}:{$match['hostname']}",
            'warning',
            "Custom Pattern Alert ({$rule->name}) on {$match['hostname']}",
            sprintf(
                "Pattern '%s' matched %d times on %s (%s) within %d minutes. Sample: %s",
                $rule->pattern,
                (int) $match['cnt'],
                $match['hostname'],
                $match['source_ip'],
                $rule->window_minutes,
                substr((string) $match['sample_msg'], 0, 200)
            ),
            $match['hostname'],
            $match['source_ip'],
            (int) $match['cnt'],
            ['pattern' => $rule->pattern, 'sample_message' => $match['sample_msg']]
        );
    }

    protected function triggerIncident(
        AlertRule $rule,
        string $dedupKey,
        string $severity,
        string $title,
        string $summary,
        string $sourceHost,
        string $sourceIp,
        int $matchCount,
        array $samplePayload = []
    ): bool {
        // Deduplicate against open incident with same dedup_key within cooldown window
        $existing = AlertIncident::where('dedup_key', $dedupKey)
            ->where('status', 'open')
            ->where('triggered_at', '>=', now()->subMinutes(max(1, (int) $rule->cooldown_minutes)))
            ->first();

        if ($existing) {
            $existing->update([
                'match_count' => $existing->match_count + $matchCount,
                'summary' => $summary,
            ]);
            $rule->update(['last_triggered_at' => now()]);
            return false;
        }

        $incident = AlertIncident::create([
            'alert_rule_id' => $rule->id,
            'dedup_key' => $dedupKey,
            'severity' => $severity,
            'title' => $title,
            'summary' => $summary,
            'source_host' => $sourceHost,
            'source_ip' => $sourceIp,
            'match_count' => $matchCount,
            'sample_payload' => $samplePayload,
            'status' => 'open',
            'triggered_at' => now(),
        ]);

        $sentChannels = $this->notifier->dispatch($incident, $rule);
        $incident->update(['notified_channels' => $sentChannels]);
        $rule->update(['last_triggered_at' => now()]);

        return true;
    }
}
