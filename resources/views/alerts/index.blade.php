@extends('layouts.app')
@section('title', 'Alerts & Pattern Rules')
@section('heading', 'Security & Operational Alerting')
@section('subheading', 'Configurable syslog pattern detection, deduplication, cooldowns, and incident response workflow')

@section('content')
<!-- Explicit Architectural Scope Banner -->
<div class="rounded-xl bg-amber-500/10 border border-amber-500/30 p-4 text-xs text-amber-200 flex items-start justify-between gap-4">
    <div>
        <div class="font-bold text-amber-300 mb-0.5">Architectural Scope: Syslog Pattern &amp; Threshold Detection vs. Full SIEM/IDS</div>
        <div>
            These alert rules evaluate incoming RFC3164/RFC5424 syslog event streams, source heartbeats, and storage metrics using sliding time-window thresholds, deduplication keys, and cooldown windows. While effective for detecting SSH brute-force attempts, authentication bursts, service crashes, and silent hosts, this engine operates on syslog telemetry rather than deep packet inspection (NIDS/Suricata), endpoint kernel telemetry (EDR), or multi-protocol cross-asset graph correlation of a full enterprise SIEM.
        </div>
    </div>
    @can('investigate-logs')
        <form method="POST" action="{{ route('alerts.evaluate') }}" class="shrink-0">
            @csrf
            <button type="submit" class="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold whitespace-nowrap">
                Evaluate Rules Now
            </button>
        </form>
    @endcan
</div>

<!-- Alert History / Incidents -->
<div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
    <div class="px-6 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div>
            <h2 class="text-sm font-bold text-white">Alert Incident History</h2>
            <p class="text-xs text-slate-400">Deduplicated incidents triggered by active rules</p>
        </div>
        <div class="flex items-center space-x-2 text-xs">
            @foreach(['' => 'All', 'open' => 'Open', 'acknowledged' => 'Acknowledged', 'resolved' => 'Resolved'] as $st => $lbl)
                <a href="{{ route('alerts.index', ['status' => $st]) }}"
                   class="px-2.5 py-1 rounded border {{ $statusFilter === $st ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-semibold' : 'bg-slate-950 text-slate-400 border-slate-800' }}">
                    {{ $lbl }}
                </a>
            @endforeach
        </div>
    </div>

    <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
            <thead class="bg-slate-950 text-slate-400 uppercase text-[11px]">
                <tr>
                    <th class="px-4 py-3">ID / Time</th>
                    <th class="px-4 py-3">Severity</th>
                    <th class="px-4 py-3">Status</th>
                    <th class="px-4 py-3">Title &amp; Summary</th>
                    <th class="px-4 py-3">Source Host</th>
                    <th class="px-4 py-3">Matches</th>
                    @can('investigate-logs')
                        <th class="px-4 py-3 text-right">Workflow</th>
                    @endcan
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/80">
                @forelse($incidents as $inc)
                    <tr class="hover:bg-slate-800/50">
                        <td class="px-4 py-3 font-mono whitespace-nowrap">
                            <div class="text-white">#{{ $inc->id }}</div>
                            <div class="text-[11px] text-slate-400">{{ $inc->triggered_at?->format('Y-m-d H:i:s') }}</div>
                        </td>
                        <td class="px-4 py-3 whitespace-nowrap">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase {{ $inc->severity === 'critical' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : ($inc->severity === 'high' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' : 'bg-amber-500/20 text-amber-300 border border-amber-500/40') }}">
                                {{ $inc->severity }}
                            </span>
                        </td>
                        <td class="px-4 py-3 whitespace-nowrap">
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono uppercase {{ $inc->status === 'open' ? 'bg-rose-500/15 text-rose-300' : ($inc->status === 'acknowledged' ? 'bg-amber-500/15 text-amber-300' : 'bg-emerald-500/15 text-emerald-300') }}">
                                {{ $inc->status }}
                            </span>
                        </td>
                        <td class="px-4 py-3 max-w-xl">
                            <div class="font-bold text-white">{{ $inc->title }}</div>
                            <div class="text-slate-300 mt-0.5">{{ $inc->summary }}</div>
                        </td>
                        <td class="px-4 py-3 font-mono text-cyan-300 whitespace-nowrap">
                            {{ $inc->source_host }} <span class="text-slate-500">({{ $inc->source_ip }})</span>
                        </td>
                        <td class="px-4 py-3 font-mono font-bold text-white">{{ $inc->match_count }}</td>
                        @can('investigate-logs')
                            <td class="px-4 py-3 text-right whitespace-nowrap space-x-1">
                                @if($inc->status === 'open')
                                    <form method="POST" action="{{ route('alerts.incidents.status', $inc) }}" class="inline">
                                        @csrf
                                        <input type="hidden" name="status" value="acknowledged">
                                        <button type="submit" class="px-2 py-1 rounded bg-amber-500/20 text-amber-300 text-[11px]">Ack</button>
                                    </form>
                                @endif
                                @if($inc->status !== 'resolved')
                                    <form method="POST" action="{{ route('alerts.incidents.status', $inc) }}" class="inline">
                                        @csrf
                                        <input type="hidden" name="status" value="resolved">
                                        <button type="submit" class="px-2 py-1 rounded bg-emerald-500/20 text-emerald-300 text-[11px]">Resolve</button>
                                    </form>
                                @endif
                            </td>
                        @endcan
                    </tr>
                @empty
                    <tr>
                        <td colspan="7" class="px-6 py-8 text-center text-slate-500">No alert incidents recorded for the selected status filter.</td>
                    </tr>
                @endforelse
            </tbody>
        </table>
    </div>
    <div class="p-4 border-t border-slate-800">
        {{ $incidents->links() }}
    </div>
</div>

<!-- Configured Alert Rules & Create Rule Form -->
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <div class="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-800">
            <h3 class="text-sm font-bold text-white">Configured Detection Rules</h3>
        </div>
        <div class="overflow-x-auto">
            <table class="w-full text-left text-xs">
                <thead class="bg-slate-950 text-slate-400 uppercase text-[11px]">
                    <tr>
                        <th class="px-4 py-3">Rule Name / Type</th>
                        <th class="px-4 py-3">Threshold &amp; Window</th>
                        <th class="px-4 py-3">Cooldown</th>
                        <th class="px-4 py-3">Channels</th>
                        <th class="px-4 py-3">State</th>
                        @can('manage-settings')
                            <th class="px-4 py-3 text-right">Actions</th>
                        @endcan
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-800/80">
                    @foreach($rules as $rule)
                        <tr>
                            <td class="px-4 py-3">
                                <div class="font-semibold text-white">{{ $rule->name }}</div>
                                <div class="text-[11px] font-mono text-cyan-400">{{ $rule->rule_type }} {{ $rule->pattern ? "('{$rule->pattern}')" : '' }}</div>
                            </td>
                            <td class="px-4 py-3 font-mono text-slate-200">&ge; {{ $rule->threshold_count }} in {{ $rule->window_minutes }}m</td>
                            <td class="px-4 py-3 font-mono text-slate-400">{{ $rule->cooldown_minutes }}m</td>
                            <td class="px-4 py-3 font-mono text-slate-300">{{ implode(', ', $rule->channels ?? ['email']) }}</td>
                            <td class="px-4 py-3">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold {{ $rule->is_enabled ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-400' }}">
                                    {{ $rule->is_enabled ? 'ENABLED' : 'DISABLED' }}
                                </span>
                            </td>
                            @can('manage-settings')
                                <td class="px-4 py-3 text-right whitespace-nowrap space-x-1">
                                    <form method="POST" action="{{ route('alerts.rules.toggle', $rule) }}" class="inline">
                                        @csrf
                                        <button type="submit" class="px-2 py-1 rounded bg-slate-800 text-slate-200 text-[11px]">
                                            {{ $rule->is_enabled ? 'Disable' : 'Enable' }}
                                        </button>
                                    </form>
                                    <form method="POST" action="{{ route('alerts.rules.destroy', $rule) }}" class="inline">
                                        @csrf
                                        @method('DELETE')
                                        <button type="submit" class="px-2 py-1 rounded bg-rose-500/15 text-rose-300 text-[11px]">Delete</button>
                                    </form>
                                </td>
                            @endcan
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    </div>

    @can('manage-settings')
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h3 class="text-sm font-bold text-white mb-3">Create Custom Alert Rule</h3>
        <form method="POST" action="{{ route('alerts.rules.store') }}" class="space-y-3 text-xs">
            @csrf
            <div>
                <label class="block text-slate-400 mb-1">Rule Name</label>
                <input type="text" name="name" required placeholder="Sudo Command Failure Burst" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
            </div>
            <div>
                <label class="block text-slate-400 mb-1">Detection Type</label>
                <select name="rule_type" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                    <option value="custom_pattern">Custom Keyword / Pattern</option>
                    <option value="auth_failure">Repeated Auth Failures</option>
                    <option value="ssh_bruteforce">SSH Brute-Force Indicator</option>
                    <option value="critical_severity">Critical &amp; Emergency Messages</option>
                    <option value="service_failure">Unexpected Service Shutdown</option>
                    <option value="disk_usage">Disk Usage Threshold (%)</option>
                    <option value="volume_spike">Sudden Log Volume Spike</option>
                    <option value="silent_source">Registered Server Silent</option>
                </select>
            </div>
            <div>
                <label class="block text-slate-400 mb-1">Match Pattern (for Custom Pattern type)</label>
                <input type="text" name="pattern" placeholder="e.g. COMMAND=/bin/su or segfault" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
            </div>
            <div class="grid grid-cols-3 gap-2">
                <div>
                    <label class="block text-slate-400 mb-1">Threshold</label>
                    <input type="number" name="threshold_count" value="5" min="1" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2.5 py-2 text-white font-mono">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Window (m)</label>
                    <input type="number" name="window_minutes" value="5" min="1" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2.5 py-2 text-white font-mono">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Cooldown (m)</label>
                    <input type="number" name="cooldown_minutes" value="15" min="1" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2.5 py-2 text-white font-mono">
                </div>
            </div>
            <div>
                <label class="block text-slate-400 mb-1">Notification Channels</label>
                <div class="flex items-center space-x-4 mt-1">
                    <label class="flex items-center space-x-1.5">
                        <input type="checkbox" name="channels[]" value="email" checked class="rounded bg-slate-950 border-slate-700">
                        <span>Email</span>
                    </label>
                    <label class="flex items-center space-x-1.5">
                        <input type="checkbox" name="channels[]" value="telegram" class="rounded bg-slate-950 border-slate-700">
                        <span>Telegram (Extensible)</span>
                    </label>
                </div>
            </div>
            <div>
                <label class="block text-slate-400 mb-1">Recipient Email(s)</label>
                <input type="text" name="recipients" value="soc-alerts@syslog.local" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
            </div>
            <button type="submit" class="w-full py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold">
                Save Alert Rule
            </button>
        </form>
    </div>
    @endcan
</div>
@endsection
