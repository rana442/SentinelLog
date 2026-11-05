@extends('layouts.app')
@section('title', 'SOC Security Dashboard')
@section('heading', 'Security Monitoring & Telemetry Dashboard')
@section('subheading', 'Live syslog ingestion rate, source health, authentication telemetry, and severity analytics')

@section('content')
<!-- Top KPI Stat Cards -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400">Events Today (UTC)</div>
        <div id="kpi-total-today" class="text-2xl font-bold text-white font-mono mt-1">{{ number_format($metrics['total_today']) }}</div>
        <div class="text-[11px] text-emerald-400 mt-1">Indexed in FTS5</div>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400">Events / Minute</div>
        <div id="kpi-epm" class="text-2xl font-bold text-cyan-400 font-mono mt-1">{{ $metrics['events_per_minute'] }}</div>
        <div class="text-[11px] text-slate-400 mt-1">5m rolling avg</div>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400">Warnings &amp; Errors (24h)</div>
        <div id="kpi-warn-err" class="text-2xl font-bold text-amber-400 font-mono mt-1">{{ number_format($metrics['warning_error_24h']) }}</div>
        <div class="text-[11px] text-amber-300/80 mt-1">Sev 3 (Err) &amp; 4 (Warn)</div>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400">Critical &amp; Emergency (24h)</div>
        <div id="kpi-crit-emerg" class="text-2xl font-bold text-rose-400 font-mono mt-1">{{ number_format($metrics['critical_emerg_24h']) }}</div>
        <div class="text-[11px] text-rose-300/80 mt-1">Sev 0?2 high priority</div>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400">Active Log Sources</div>
        <div class="flex items-baseline space-x-1 mt-1">
            <span id="kpi-active-sources" class="text-2xl font-bold text-emerald-400 font-mono">{{ $active_sources_count }}</span>
            <span class="text-xs text-slate-500 font-mono">/ {{ $total_sources_count }}</span>
        </div>
        <div class="text-[11px] text-slate-400 mt-1">{{ count($silent_sources) }} silent / delayed</div>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div class="text-xs text-slate-400">Storage Quota Usage</div>
        <div id="kpi-disk" class="text-2xl font-bold {{ $disk['used_percent'] >= 75 ? 'text-rose-400' : 'text-slate-100' }} font-mono mt-1">{{ $disk['used_percent'] }}%</div>
        <div class="text-[11px] text-slate-400 mt-1">{{ $disk['free_gb'] }} GiB free of {{ $disk['total_gb'] }} GiB</div>
    </div>
</div>

<!-- Charts Row: Hourly Trend, Daily Trend, and Severity Distribution -->
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-bold text-white">Log Volume Trend by Hour (Last 24h)</h2>
            <span class="text-[11px] text-slate-400 font-mono">UTC</span>
        </div>
        <div class="h-52">
            <canvas id="chart-hourly"></canvas>
        </div>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-bold text-white">Log Volume Trend by Day (7d)</h2>
            <span class="text-[11px] text-slate-400 font-mono">Daily</span>
        </div>
        <div class="h-52">
            <canvas id="chart-daily"></canvas>
        </div>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-bold text-white">Severity Distribution (24h)</h2>
            <span class="text-[11px] text-slate-400 font-mono">RFC 5424</span>
        </div>
        <div class="h-52">
            <canvas id="chart-severity"></canvas>
        </div>
    </div>
</div>

<!-- Sources Stopped Sending Logs & Top Hosts / Top Applications -->
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Silent / Delayed Sources -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-bold text-white">Sources Stopped / Delayed</h2>
            <a href="{{ route('sources.index') }}" class="text-xs text-cyan-400 hover:underline">Manage &rarr;</a>
        </div>
        @if(empty($silent_sources))
            <div class="text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-4">
                All enabled log sources have reported within their configured heartbeat window.
            </div>
        @else
            <div class="space-y-2.5">
                @foreach($silent_sources as $s)
                    <div class="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                        <div>
                            <div class="font-mono font-semibold text-white">{{ $s['hostname'] }}</div>
                            <div class="text-[11px] text-slate-400 font-mono">{{ $s['ip_address'] }} &bull; {{ $s['environment'] }}</div>
                        </div>
                        <div class="text-right">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold {{ $s['status'] === 'Offline' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-amber-500/20 text-amber-300 border border-amber-500/40' }}">
                                {{ strtoupper($s['status']) }}
                            </span>
                            <div class="text-[11px] text-slate-400 mt-1">{{ $s['last_seen_human'] }}</div>
                        </div>
                    </div>
                @endforeach
            </div>
        @endif
    </div>

    <!-- Top Log-Generating Servers -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-bold text-white">Top Log-Generating Servers (24h)</h2>
            <span class="text-[11px] text-slate-400">By Host</span>
        </div>
        <div class="space-y-2">
            @forelse($metrics['top_hosts'] as $h)
                <a href="{{ route('logs.explorer', ['hostname' => $h['hostname']]) }}" class="flex items-center justify-between p-2 rounded-lg bg-slate-950 hover:bg-slate-800/80 border border-slate-800 text-xs transition">
                    <div>
                        <span class="font-mono text-cyan-300 font-medium">{{ $h['hostname'] }}</span>
                        <span class="text-slate-500 font-mono ml-1.5">({{ $h['source_ip'] }})</span>
                    </div>
                    <span class="font-mono font-bold text-white">{{ number_format($h['total']) }}</span>
                </a>
            @empty
                <div class="text-xs text-slate-500 py-4 text-center">No host telemetry recorded yet.</div>
            @endforelse
        </div>
    </div>

    <!-- Top Applications and Processes -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-bold text-white">Top Applications &amp; Processes (24h)</h2>
            <span class="text-[11px] text-slate-400">By App-Name</span>
        </div>
        <div class="space-y-2">
            @forelse($metrics['top_apps'] as $app)
                <a href="{{ route('logs.explorer', ['app_name' => $app['app_name']]) }}" class="flex items-center justify-between p-2 rounded-lg bg-slate-950 hover:bg-slate-800/80 border border-slate-800 text-xs transition">
                    <span class="font-mono text-slate-200">{{ $app['app_name'] }}</span>
                    <span class="font-mono font-bold text-cyan-300">{{ number_format($app['total']) }}</span>
                </a>
            @empty
                <div class="text-xs text-slate-500 py-4 text-center">No application telemetry recorded yet.</div>
            @endforelse
        </div>
    </div>
</div>

<!-- Security Telemetry Panels: Auth Failures, SSH Activity, Service Errors -->
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Recent Authentication Failures -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-bold text-rose-300">Recent Authentication Failures</h2>
            <a href="{{ route('logs.explorer', ['quick_filter' => 'auth_failure']) }}" class="text-xs text-cyan-400 hover:underline">View All</a>
        </div>
        <div class="space-y-2 text-xs">
            @forelse($metrics['recent_auth_failures'] as $ev)
                <div onclick="inspectEvent({{ (int)$ev['id'] }})" class="cursor-pointer p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800">
                    <div class="flex justify-between text-[11px] text-slate-400 font-mono">
                        <span class="text-rose-300 font-semibold">{{ $ev['hostname'] }} ({{ $ev['source_ip'] }})</span>
                        <span>{{ $ev['received_at'] }}</span>
                    </div>
                    <div class="font-mono text-slate-200 truncate mt-1">{{ $ev['message'] }}</div>
                </div>
            @empty
                <div class="text-xs text-slate-500 py-4 text-center">No recent authentication failures.</div>
            @endforelse
        </div>
    </div>

    <!-- SSH Login Successes & Failures -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-bold text-cyan-300">SSH Login Successes &amp; Failures</h2>
            <a href="{{ route('logs.explorer', ['quick_filter' => 'ssh_auth']) }}" class="text-xs text-cyan-400 hover:underline">View All</a>
        </div>
        <div class="space-y-2 text-xs">
            @forelse($metrics['recent_ssh_events'] as $ev)
                <div onclick="inspectEvent({{ (int)$ev['id'] }})" class="cursor-pointer p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800">
                    <div class="flex justify-between text-[11px] text-slate-400 font-mono">
                        <span class="text-cyan-300">{{ $ev['hostname'] }} [{{ $ev['app_name'] }}]</span>
                        <span>{{ $ev['received_at'] }}</span>
                    </div>
                    <div class="font-mono text-slate-200 truncate mt-1">{{ $ev['message'] }}</div>
                </div>
            @empty
                <div class="text-xs text-slate-500 py-4 text-center">No recent SSH events recorded.</div>
            @endforelse
        </div>
    </div>

    <!-- Service Failures & System Errors -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-bold text-amber-300">Service Failures &amp; System Errors</h2>
            <a href="{{ route('logs.explorer', ['quick_filter' => 'service_failure']) }}" class="text-xs text-cyan-400 hover:underline">View All</a>
        </div>
        <div class="space-y-2 text-xs">
            @forelse($metrics['recent_service_errors'] as $ev)
                <div onclick="inspectEvent({{ (int)$ev['id'] }})" class="cursor-pointer p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800">
                    <div class="flex justify-between text-[11px] text-slate-400 font-mono">
                        <span class="text-amber-300">{{ $ev['hostname'] }} ({{ $ev['app_name'] }})</span>
                        <span>{{ $ev['received_at'] }}</span>
                    </div>
                    <div class="font-mono text-slate-200 truncate mt-1">{{ $ev['message'] }}</div>
                </div>
            @empty
                <div class="text-xs text-slate-500 py-4 text-center">No recent service errors.</div>
            @endforelse
        </div>
    </div>
</div>

<!-- Recent Critical Events Table -->
<div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
    <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
        <div>
            <h2 class="text-sm font-bold text-white">Recent Critical, Alert &amp; Emergency Events</h2>
            <p class="text-xs text-slate-400">Click any row to inspect parsed RFC fields and raw message</p>
        </div>
        <a href="{{ route('logs.explorer', ['quick_filter' => 'critical_only']) }}" class="text-xs px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 font-medium">
            Investigate in Explorer &rarr;
        </a>
    </div>
    <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
            <thead class="bg-slate-950/70 text-slate-400 uppercase text-[11px]">
                <tr>
                    <th class="px-4 py-3">Timestamp (UTC)</th>
                    <th class="px-4 py-3">Severity</th>
                    <th class="px-4 py-3">Host / IP</th>
                    <th class="px-4 py-3">Proto</th>
                    <th class="px-4 py-3">Facility / App</th>
                    <th class="px-4 py-3">Message</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/80 font-mono">
                @forelse($metrics['recent_critical'] as $ev)
                    <tr onclick="inspectEvent({{ (int)$ev['id'] }})" class="hover:bg-slate-800/60 cursor-pointer transition">
                        <td class="px-4 py-2.5 whitespace-nowrap text-slate-300">{{ $ev['received_at'] }}</td>
                        <td class="px-4 py-2.5 whitespace-nowrap">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                                {{ strtoupper($ev['severity']) }}
                            </span>
                        </td>
                        <td class="px-4 py-2.5 whitespace-nowrap text-cyan-300">{{ $ev['hostname'] }} <span class="text-slate-500">({{ $ev['source_ip'] }})</span></td>
                        <td class="px-4 py-2.5 whitespace-nowrap text-slate-400">{{ $ev['protocol'] }}</td>
                        <td class="px-4 py-2.5 whitespace-nowrap text-slate-300">{{ $ev['facility'] }}/{{ $ev['app_name'] }}</td>
                        <td class="px-4 py-2.5 text-slate-100 max-w-xl truncate">{{ $ev['message'] }}</td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="6" class="px-4 py-8 text-center text-slate-500 font-sans">No critical or emergency events recorded in the hot index.</td>
                    </tr>
                @endforelse
            </tbody>
        </table>
    </div>
</div>
@endsection

@push('scripts')
<script>
    const hourlyData = @json($metrics['hourly_trend']);
    const dailyData = @json($metrics['daily_trend']);
    const sevDist = @json($metrics['severity_distribution']);

    new Chart(document.getElementById('chart-hourly'), {
        type: 'line',
        data: {
            labels: hourlyData.map(r => r.hour_bucket.slice(11)),
            datasets: [{
                label: 'Events / Hr',
                data: hourlyData.map(r => r.total),
                borderColor: '#22d3ee',
                backgroundColor: 'rgba(34, 211, 238, 0.12)',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: '#1e293b' } },
                y: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: '#1e293b' }, beginAtZero: true }
            }
        }
    });

    new Chart(document.getElementById('chart-daily'), {
        type: 'bar',
        data: {
            labels: dailyData.map(r => r.day_bucket.slice(5)),
            datasets: [{
                label: 'Events / Day',
                data: dailyData.map(r => r.total),
                backgroundColor: '#38bdf8',
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: '#1e293b' } },
                y: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: '#1e293b' }, beginAtZero: true }
            }
        }
    });

    new Chart(document.getElementById('chart-severity'), {
        type: 'doughnut',
        data: {
            labels: ['Emerg', 'Alert', 'Crit', 'Error', 'Warn', 'Notice', 'Info', 'Debug'],
            datasets: [{
                data: [sevDist[0]||0, sevDist[1]||0, sevDist[2]||0, sevDist[3]||0, sevDist[4]||0, sevDist[5]||0, sevDist[6]||0, sevDist[7]||0],
                backgroundColor: ['#ef4444', '#f43f5e', '#fb7185', '#f97316', '#f59e0b', '#06b6d4', '#10b981', '#64748b'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#cbd5e1', font: { size: 10 }, boxWidth: 10 } }
            }
        }
    });

    // Live polling every 10s without full-page reload
    setInterval(async () => {
        try {
            const resp = await fetch('{{ route("dashboard.metrics") }}', { headers: { 'Accept': 'application/json' } });
            if (!resp.ok) return;
            const d = await resp.json();
            document.getElementById('kpi-total-today').textContent = Number(d.metrics.total_today).toLocaleString();
            document.getElementById('kpi-epm').textContent = d.metrics.events_per_minute;
            document.getElementById('kpi-warn-err').textContent = Number(d.metrics.warning_error_24h).toLocaleString();
            document.getElementById('kpi-crit-emerg').textContent = Number(d.metrics.critical_emerg_24h).toLocaleString();
            document.getElementById('kpi-active-sources').textContent = d.active_sources_count;
            document.getElementById('kpi-disk').textContent = d.disk.used_percent + '%';
        } catch (e) {}
    }, 10000);
</script>
@endpush
