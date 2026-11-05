<?php

namespace App\Http\Controllers;

use App\Models\SystemSetting;
use App\Services\AuditService;
use App\Services\RsyslogConfigService;
use App\Services\SyslogIndexService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Gate;

class SettingController extends Controller
{
    public function index(SyslogIndexService $index)
    {
        Gate::authorize('manage-settings');

        $settings = SystemSetting::pluck('value', 'key')->toArray();
        $pdo = $index->pdo();
        $totalHotEvents = (int) $pdo->query("SELECT COUNT(*) FROM syslog_events")->fetchColumn();
        $pinnedEvents = (int) $pdo->query("SELECT COUNT(*) FROM syslog_events WHERE is_pinned = 1")->fetchColumn();

        $indexFile = config('syslog.index_db', '/var/lib/central-syslog/index/syslog_hot.sqlite');
        $indexSizeMb = is_file($indexFile) ? round(filesize($indexFile) / (1024 * 1024), 2) : 0;

        $hostsDir = config('syslog.hosts_dir', '/var/log/central-syslog/hosts');
        $totalDisk = @disk_total_space($hostsDir) ?: 1;
        $freeDisk = @disk_free_space($hostsDir) ?: 0;

        return view('settings.index', [
            'settings' => $settings,
            'totalHotEvents' => $totalHotEvents,
            'pinnedEvents' => $pinnedEvents,
            'indexSizeMb' => $indexSizeMb,
            'diskUsedPercent' => (int) round((($totalDisk - $freeDisk) / $totalDisk) * 100),
            'diskFreeGb' => round($freeDisk / (1024 ** 3), 2),
            'diskTotalGb' => round($totalDisk / (1024 ** 3), 2),
        ]);
    }

    public function update(Request $request)
    {
        Gate::authorize('manage-settings');

        $validated = $request->validate([
            'hot_retention_days' => ['required', 'integer', 'min:1', 'max:365'],
            'archive_retention_days' => ['required', 'integer', 'min:7', 'max:3650'],
            'disk_warning_percent' => ['required', 'integer', 'min:50', 'max:95'],
            'disk_critical_percent' => ['required', 'integer', 'min:60', 'max:98'],
            'disk_emergency_prune_percent' => ['required', 'integer', 'min:70', 'max:99'],
            'default_timezone' => ['required', 'string', 'max:64'],
            'restrict_unauthorized_sources' => ['nullable', 'boolean'],
            'notification_email' => ['required', 'email', 'max:191'],
            'telegram_bot_token' => ['nullable', 'string', 'max:191'],
            'telegram_chat_id' => ['nullable', 'string', 'max:64'],
        ]);

        SystemSetting::setValue('hot_retention_days', $validated['hot_retention_days'], 'retention');
        SystemSetting::setValue('archive_retention_days', $validated['archive_retention_days'], 'retention');
        SystemSetting::setValue('disk_warning_percent', $validated['disk_warning_percent'], 'storage');
        SystemSetting::setValue('disk_critical_percent', $validated['disk_critical_percent'], 'storage');
        SystemSetting::setValue('disk_emergency_prune_percent', $validated['disk_emergency_prune_percent'], 'storage');
        SystemSetting::setValue('default_timezone', $validated['default_timezone'], 'general');
        SystemSetting::setValue('restrict_unauthorized_sources', $request->boolean('restrict_unauthorized_sources') ? '1' : '0', 'security');
        SystemSetting::setValue('notification_email', $validated['notification_email'], 'notifications');
        if ($request->filled('telegram_bot_token')) {
            SystemSetting::setValue('telegram_bot_token', $validated['telegram_bot_token'], 'notifications');
        }
        SystemSetting::setValue('telegram_chat_id', (string) ($validated['telegram_chat_id'] ?? ''), 'notifications');

        RsyslogConfigService::syncAllowedSenders();

        AuditService::record('settings.updated', 'system_settings', 'global', [
            'hot_retention_days' => $validated['hot_retention_days'],
            'archive_retention_days' => $validated['archive_retention_days'],
            'disk_warning_percent' => $validated['disk_warning_percent'],
            'restrict_unauthorized_sources' => $request->boolean('restrict_unauthorized_sources'),
        ]);

        return back()->with('status', 'Retention, storage quota watermarks, and notification settings updated.');
    }

    public function runMaintenance()
    {
        Gate::authorize('manage-settings');

        Artisan::call('syslog:maintenance');
        $output = trim(Artisan::output());

        return back()->with('status', $output ?: 'Retention maintenance executed.');
    }
}
