@extends('layouts.app')
@section('title', 'Retention, Storage & System Settings')
@section('heading', 'Retention Policy, Storage Quotas & System Configuration')
@section('subheading', 'Manage hot/cold retention lifecycles, disk watermarks, source ACL enforcement, and operator password')

@section('content')
<!-- Storage & Index Telemetry -->
<div class="grid grid-cols-1 md:grid-cols-4 gap-4">
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400">Hot Indexed Events (SQLite FTS5)</div>
        <div class="text-2xl font-bold text-white font-mono mt-1">{{ number_format($totalHotEvents) }}</div>
        <div class="text-[11px] text-slate-400 mt-1">Index Size: {{ $indexSizeMb }} MB</div>
    </div>
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400">Pinned Investigation Events</div>
        <div class="text-2xl font-bold text-amber-400 font-mono mt-1">{{ number_format($pinnedEvents) }}</div>
        <div class="text-[11px] text-amber-300/80 mt-1">Exempt from auto-pruning</div>
    </div>
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400">Disk Partition Usage</div>
        <div class="text-2xl font-bold text-cyan-400 font-mono mt-1">{{ $diskUsedPercent }}%</div>
        <div class="text-[11px] text-slate-400 mt-1">{{ $diskFreeGb }} GiB free of {{ $diskTotalGb }} GiB</div>
    </div>
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
        <div class="text-xs text-slate-400">On-Demand Retention Task</div>
        <form method="POST" action="{{ route('settings.maintenance') }}" class="mt-2">
            @csrf
            <button type="submit" class="w-full py-2 px-3 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-xs font-bold">
                Run Retention &amp; Quota Check Now
            </button>
        </form>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <div class="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6">
        <h3 class="text-sm font-bold text-white mb-4">Retention, Quota &amp; Notification Configuration</h3>
        <form method="POST" action="{{ route('settings.update') }}" class="space-y-4 text-xs">
            @csrf
            @method('PUT')
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                    <label class="block text-slate-400 mb-1">Hot Searchable Retention (Days)</label>
                    <input type="number" name="hot_retention_days" value="{{ $settings['hot_retention_days'] ?? 30 }}" min="1" max="365" required
                        class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Archived (.gz) File Retention (Days)</label>
                    <input type="number" name="archive_retention_days" value="{{ $settings['archive_retention_days'] ?? 90 }}" min="7" max="3650" required
                        class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Disk Warning Threshold (%)</label>
                    <input type="number" name="disk_warning_percent" value="{{ $settings['disk_warning_percent'] ?? 75 }}" min="50" max="95" required
                        class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Disk Critical Alert Threshold (%)</label>
                    <input type="number" name="disk_critical_percent" value="{{ $settings['disk_critical_percent'] ?? 85 }}" min="60" max="98" required
                        class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Emergency Unpinned Prune Watermark (%)</label>
                    <input type="number" name="disk_emergency_prune_percent" value="{{ $settings['disk_emergency_prune_percent'] ?? 90 }}" min="70" max="99" required
                        class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Default Portal Timezone</label>
                    <select name="default_timezone" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                        @foreach(['UTC', 'Asia/Dhaka', 'Europe/London', 'America/New_York'] as $tz)
                            <option value="{{ $tz }}" @selected(($settings['default_timezone'] ?? 'UTC') === $tz)>{{ $tz }}</option>
                        @endforeach
                    </select>
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Default SOC Alert Email</label>
                    <input type="email" name="notification_email" value="{{ $settings['notification_email'] ?? 'soc-alerts@syslog.local' }}" required
                        class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Telegram Chat ID (Optional)</label>
                    <input type="text" name="telegram_chat_id" value="{{ $settings['telegram_chat_id'] ?? '' }}" placeholder="-100123456789"
                        class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                </div>
            </div>

            <div>
                <label class="block text-slate-400 mb-1">Telegram Bot Token (Leave blank to keep existing)</label>
                <input type="password" name="telegram_bot_token" placeholder="123456:ABC-DEF..."
                    class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
            </div>

            <div class="pt-2">
                <label class="flex items-center space-x-2 text-slate-200">
                    <input type="checkbox" name="restrict_unauthorized_sources" value="1" @checked(($settings['restrict_unauthorized_sources'] ?? '1') === '1')
                        class="rounded bg-slate-950 border-slate-700">
                    <span>Enforce rsyslog <code class="text-cyan-300">$AllowedSender</code> ACL (Reject syslog packets from unregistered subnets/IPs)</span>
                </label>
            </div>

            <button type="submit" class="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold">
                Save Platform Settings
            </button>
        </form>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <h3 class="text-sm font-bold text-white">Change Your Operator Password</h3>
        <form method="POST" action="{{ route('profile.password') }}" class="space-y-3 text-xs">
            @csrf
            <div>
                <label class="block text-slate-400 mb-1">Current Password</label>
                <input type="password" name="current_password" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
            </div>
            <div>
                <label class="block text-slate-400 mb-1">New Password</label>
                <input type="password" name="password" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
            </div>
            <div>
                <label class="block text-slate-400 mb-1">Confirm New Password</label>
                <input type="password" name="password_confirmation" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
            </div>
            <button type="submit" class="w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 font-bold">
                Update Password
            </button>
        </form>
    </div>
</div>
@endsection
