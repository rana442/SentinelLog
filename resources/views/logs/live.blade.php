@extends('layouts.app')
@section('title', 'Live Syslog Stream')
@section('heading', 'Real-Time Syslog Tail')
@section('subheading', 'Live streaming syslog events with zero page reloads and XSS-safe rendering')

@section('content')
<div class="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
    <div class="flex flex-wrap items-center gap-3 text-xs">
        <span id="live-indicator" class="px-2.5 py-1 rounded-md bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold flex items-center gap-1.5">
            <span class="h-2 w-2 rounded-full bg-emerald-400 animate-ping"></span>
            STREAMING LIVE
        </span>

        <select id="live-host" class="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-slate-200">
            <option value="">All Hosts</option>
            @foreach($facets['hosts'] as $h)
                <option value="{{ $h }}">{{ $h }}</option>
            @endforeach
        </select>

        <select id="live-sev" class="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-slate-200">
            <option value="">All Severities (0?7)</option>
            <option value="2">Critical &amp; Above (0?2)</option>
            <option value="3">Error &amp; Above (0?3)</option>
            <option value="4">Warning &amp; Above (0?4)</option>
        </select>

        <select id="live-proto" class="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-slate-200">
            <option value="">All Transports</option>
            <option value="UDP">UDP</option>
            <option value="TCP">TCP</option>
            <option value="TLS">TLS</option>
            <option value="LOCAL">LOCAL</option>
        </select>
    </div>

    <div class="flex items-center gap-2">
        <button id="btn-toggle-stream" onclick="toggleStream()" class="px-3 py-1.5 rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/40 text-xs font-semibold">
            Pause Stream
        </button>
    </div>
</div>

<div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
    <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
            <thead class="bg-slate-950 text-slate-400 uppercase text-[11px]">
                <tr>
                    <th class="px-4 py-3">ID</th>
                    <th class="px-4 py-3">Received (UTC)</th>
                    <th class="px-4 py-3">Severity</th>
                    <th class="px-4 py-3">Proto</th>
                    <th class="px-4 py-3">Host / IP</th>
                    <th class="px-4 py-3">App / Facility</th>
                    <th class="px-4 py-3">Message</th>
                </tr>
            </thead>
            <tbody id="live-log-tbody" class="divide-y divide-slate-800/80 font-mono">
                @foreach($initialEvents as $ev)
                    <tr onclick="inspectEvent({{ (int)$ev['id'] }})" class="hover:bg-slate-800/70 cursor-pointer">
                        <td class="px-4 py-2 text-slate-500">#{{ $ev['id'] }}</td>
                        <td class="px-4 py-2 whitespace-nowrap text-slate-300">{{ $ev['received_at'] }}</td>
                        <td class="px-4 py-2 whitespace-nowrap uppercase">{{ $ev['severity'] }}</td>
                        <td class="px-4 py-2 whitespace-nowrap text-slate-400">{{ $ev['protocol'] }}</td>
                        <td class="px-4 py-2 whitespace-nowrap text-cyan-300">{{ $ev['hostname'] }} ({{ $ev['source_ip'] }})</td>
                        <td class="px-4 py-2 whitespace-nowrap text-slate-300">{{ $ev['app_name'] }} ({{ $ev['facility'] }})</td>
                        <td class="px-4 py-2 text-slate-100 max-w-2xl truncate">{{ $ev['message'] }}</td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>
</div>
@endsection

@push('scripts')
<script>
    let streaming = true;
    let maxId = {{ !empty($initialEvents) ? (int)$initialEvents[0]['id'] : 0 }};

    function toggleStream() {
        streaming = !streaming;
        const btn = document.getElementById('btn-toggle-stream');
        const ind = document.getElementById('live-indicator');
        if (streaming) {
            btn.textContent = 'Pause Stream';
            ind.textContent = 'STREAMING LIVE';
            ind.className = 'px-2.5 py-1 rounded-md bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold';
        } else {
            btn.textContent = 'Resume Stream';
            ind.textContent = 'PAUSED';
            ind.className = 'px-2.5 py-1 rounded-md bg-amber-500/15 text-amber-300 border border-amber-500/30 font-semibold';
        }
    }

    setInterval(async () => {
        if (!streaming) return;
        const host = document.getElementById('live-host').value;
        const sev = document.getElementById('live-sev').value;
        const proto = document.getElementById('live-proto').value;
        const params = new URLSearchParams({ after_id: maxId, hostname: host, max_severity: sev, protocol: proto });

        try {
            const resp = await fetch(`{{ route('logs.poll') }}?${params.toString()}`, { headers: { 'Accept': 'application/json' } });
            if (!resp.ok) return;
            const data = await resp.json();
            if (!data.events || data.events.length === 0) return;

            const tbody = document.getElementById('live-log-tbody');
            const rows = data.events.slice().reverse();
            for (const ev of rows) {
                if (ev.id > maxId) maxId = ev.id;
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-slate-800/70 cursor-pointer bg-cyan-500/5 transition';
                tr.onclick = () => inspectEvent(ev.id);
                tr.innerHTML = `
                    <td class="px-4 py-2 text-slate-500">#${escapeHtml(ev.id)}</td>
                    <td class="px-4 py-2 whitespace-nowrap text-slate-300">${escapeHtml(ev.received_at)}</td>
                    <td class="px-4 py-2 whitespace-nowrap">${severityBadgeHtml(ev.severity_num, ev.severity)}</td>
                    <td class="px-4 py-2 whitespace-nowrap text-slate-400">${escapeHtml(ev.protocol)}</td>
                    <td class="px-4 py-2 whitespace-nowrap text-cyan-300">${escapeHtml(ev.hostname)} (${escapeHtml(ev.source_ip)})</td>
                    <td class="px-4 py-2 whitespace-nowrap text-slate-300">${escapeHtml(ev.app_name)} (${escapeHtml(ev.facility)})</td>
                    <td class="px-4 py-2 text-slate-100 max-w-2xl truncate">${escapeHtml(ev.message)}</td>
                `;
                tbody.prepend(tr);
                while (tbody.children.length > 150) {
                    tbody.removeChild(tbody.lastElementChild);
                }
            }
        } catch (e) {}
    }, 2500);
</script>
@endpush
