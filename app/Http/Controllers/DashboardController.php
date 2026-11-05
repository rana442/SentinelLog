<?php

namespace App\Http\Controllers;

use App\Models\AlertIncident;
use App\Models\LogSource;
use App\Models\SystemSetting;
use App\Services\SyslogIndexService;
use Illuminate\Http\Request;

class DashboardController extends Controller
{
    public function index(Request $request, SyslogIndexService $index)
    {
        $payload = $this->compileDashboardData($index);
        $timezone = $request->user()?->timezone ?: SystemSetting::getValue('default_timezone', 'UTC');

        return view('dashboard.index', array_merge($payload, [
            'displayTimezone' => $timezone,
        ]));
    }

    public function liveMetrics(SyslogIndexService $index)
    {
        return response()->json($this->compileDashboardData($index));
    }

    protected function compileDashboardData(SyslogIndexService $index): array
    {
        $metrics = $index->getDashboardMetrics();
        $sources = LogSource::orderByDesc('last_seen_at')->get();

        $activeSourcesCount = 0;
        $silentSources = [];
        foreach ($sources as $src) {
            $status = $src->healthStatus();
            if ($status === 'Online') {
                $activeSourcesCount++;
            } elseif (in_array($status, ['Offline', 'Delayed'], true) && $src->is_enabled) {
                $silentSources[] = [
                    'id' => $src->id,
                    'hostname' => $src->hostname,
                    'ip_address' => $src->ip_address,
                    'status' => $status,
                    'last_seen_human' => $src->last_seen_at ? $src->last_seen_at->diffForHumans() : 'Never',
                    'environment' => $src->environment,
                ];
            }
        }

        $hostsDir = config('syslog.hosts_dir', '/var/log/central-syslog/hosts');
        $totalBytes = @disk_total_space($hostsDir) ?: 1;
        $freeBytes = @disk_free_space($hostsDir) ?: 0;
        $usedBytes = $totalBytes - $freeBytes;
        $diskPercent = (int) round(($usedBytes / $totalBytes) * 100);

        $openAlertsCount = AlertIncident::where('status', 'open')->count();

        return [
            'metrics' => $metrics,
            'active_sources_count' => $activeSourcesCount,
            'total_sources_count' => $sources->count(),
            'silent_sources' => $silentSources,
            'open_alerts_count' => $openAlertsCount,
            'disk' => [
                'used_percent' => $diskPercent,
                'used_gb' => round($usedBytes / (1024 ** 3), 2),
                'total_gb' => round($totalBytes / (1024 ** 3), 2),
                'free_gb' => round($freeBytes / (1024 ** 3), 2),
            ],
            'server_time_utc' => now()->utc()->toIso8601String(),
        ];
    }
}
