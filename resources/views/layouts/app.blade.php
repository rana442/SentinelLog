<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>@yield('title', 'SOC Console') ? SentinelLog Central Syslog</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        slate: { 850: '#111827', 925: '#0b1120', 950: '#060a13' }
                    }
                }
            }
        }
    </script>
    <style>
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #0f172a; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #475569; }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 antialiased min-h-screen flex flex-col md:flex-row selection:bg-cyan-500 selection:text-slate-950">

    <!-- Mobile Top Header -->
    <div class="md:hidden flex items-center justify-between bg-slate-900 border-b border-slate-800 px-4 py-3">
        <div class="flex items-center space-x-2">
            <span class="h-3 w-3 rounded-full bg-emerald-400 animate-pulse"></span>
            <span class="font-bold tracking-wider text-cyan-400">SENTINELLOG</span>
        </div>
        <button onclick="document.getElementById('sidebar-nav').classList.toggle('hidden')" class="text-slate-300 hover:text-white px-2 py-1 rounded border border-slate-700 text-xs">
            Menu
        </button>
    </div>

    <!-- Sidebar Navigation -->
    <aside id="sidebar-nav" class="hidden md:flex md:flex-col w-full md:w-64 bg-slate-900/95 border-r border-slate-800 shrink-0 justify-between">
        <div>
            <div class="px-6 py-5 border-b border-slate-800 flex items-center space-x-3">
                <div class="h-9 w-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-mono font-bold">
                    SL
                </div>
                <div>
                    <div class="font-bold text-white tracking-wide text-sm">SentinelLog SIEM-Lite</div>
                    <div class="text-[11px] text-slate-400 flex items-center gap-1.5">
                        <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
                        UDP/TCP 514 &bull; TLS 6514
                    </div>
                </div>
            </div>

            <div class="px-4 py-3 border-b border-slate-800/80 bg-slate-950/40">
                <div class="text-xs font-medium text-slate-200 truncate">{{ auth()->user()->name }}</div>
                <div class="flex items-center justify-between mt-1">
                    <span class="text-[11px] px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-medium">
                        {{ auth()->user()->roleLabel() }}
                    </span>
                    <span class="text-[11px] text-slate-400 font-mono">{{ auth()->user()->timezone ?? 'UTC' }}</span>
                </div>
            </div>

            <nav class="p-3 space-y-1 text-sm">
                <a href="{{ route('dashboard') }}" class="flex items-center justify-between px-3 py-2.5 rounded-lg transition {{ request()->routeIs('dashboard') ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-semibold' : 'text-slate-300 hover:bg-slate-800/70 hover:text-white' }}">
                    <span>Dashboard</span>
                    <span class="text-[10px] font-mono text-slate-400">SOC</span>
                </a>

                <a href="{{ route('logs.live') }}" class="flex items-center justify-between px-3 py-2.5 rounded-lg transition {{ request()->routeIs('logs.live') ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-semibold' : 'text-slate-300 hover:bg-slate-800/70 hover:text-white' }}">
                    <span>Live Logs</span>
                    <span class="flex h-2 w-2 relative">
                        <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                        <span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                    </span>
                </a>

                <a href="{{ route('logs.explorer') }}" class="flex items-center justify-between px-3 py-2.5 rounded-lg transition {{ request()->routeIs('logs.explorer') ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-semibold' : 'text-slate-300 hover:bg-slate-800/70 hover:text-white' }}">
                    <span>Log Explorer</span>
                    <span class="text-[10px] font-mono text-slate-400">FTS5</span>
                </a>

                <a href="{{ route('sources.index') }}" class="flex items-center justify-between px-3 py-2.5 rounded-lg transition {{ request()->routeIs('sources.*') ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-semibold' : 'text-slate-300 hover:bg-slate-800/70 hover:text-white' }}">
                    <span>Sources</span>
                    <span class="text-[10px] font-mono text-slate-400">ACL</span>
                </a>

                <a href="{{ route('alerts.index') }}" class="flex items-center justify-between px-3 py-2.5 rounded-lg transition {{ request()->routeIs('alerts.*') ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-semibold' : 'text-slate-300 hover:bg-slate-800/70 hover:text-white' }}">
                    <span>Alerts</span>
                    @php $openIncCount = \App\Models\AlertIncident::where('status', 'open')->count(); @endphp
                    @if($openIncCount > 0)
                        <span class="px-1.5 py-0.5 text-[10px] font-bold rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">{{ $openIncCount }}</span>
                    @endif
                </a>

                @can('manage-users')
                <a href="{{ route('users.index') }}" class="flex items-center justify-between px-3 py-2.5 rounded-lg transition {{ request()->routeIs('users.*') ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-semibold' : 'text-slate-300 hover:bg-slate-800/70 hover:text-white' }}">
                    <span>Users</span>
                    <span class="text-[10px] font-mono text-slate-400">RBAC</span>
                </a>
                @endcan

                <a href="{{ route('audit.index') }}" class="flex items-center justify-between px-3 py-2.5 rounded-lg transition {{ request()->routeIs('audit.*') ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-semibold' : 'text-slate-300 hover:bg-slate-800/70 hover:text-white' }}">
                    <span>Audit Trail</span>
                    <span class="text-[10px] font-mono text-slate-400">SHA256</span>
                </a>

                @can('manage-settings')
                <a href="{{ route('settings.index') }}" class="flex items-center justify-between px-3 py-2.5 rounded-lg transition {{ request()->routeIs('settings.*') ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-semibold' : 'text-slate-300 hover:bg-slate-800/70 hover:text-white' }}">
                    <span>Settings</span>
                    <span class="text-[10px] font-mono text-slate-400">CFG</span>
                </a>
                @endcan
            </nav>
        </div>

        <div class="p-4 border-t border-slate-800 space-y-2">
            <form method="POST" action="{{ route('logout') }}">
                @csrf
                <button type="submit" class="w-full text-left px-3 py-2 rounded-lg text-xs font-medium text-rose-300 hover:bg-rose-500/15 border border-transparent hover:border-rose-500/30 transition flex items-center justify-between">
                    <span>Logout Session</span>
                    <span>&rarr;</span>
                </button>
            </form>
            <div class="text-[11px] text-slate-500 font-mono px-1">
                Host: 103.72.109.7 &bull; UTC {{ now()->utc()->format('H:i') }}
            </div>
        </div>
    </aside>

    <!-- Main Content Area -->
    <main class="flex-1 flex flex-col min-w-0 overflow-x-hidden">
        <!-- Top Status Bar -->
        <header class="bg-slate-900/70 border-b border-slate-800 px-6 py-3.5 flex flex-wrap items-center justify-between gap-3">
            <div>
                <h1 class="text-lg font-bold text-white">@yield('heading', 'Security Operations Dashboard')</h1>
                <p class="text-xs text-slate-400">@yield('subheading', 'Real-time centralized syslog monitoring, search, and incident investigation')</p>
            </div>
            <div class="flex items-center space-x-3 text-xs">
                <span class="px-2.5 py-1 rounded-md bg-slate-800 border border-slate-700 text-slate-300 font-mono">
                    TZ: {{ $displayTimezone ?? (auth()->user()->timezone ?? 'UTC') }}
                </span>
                <span class="px-2.5 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 font-mono">
                    rsyslogd: active
                </span>
            </div>
        </header>

        <div class="p-6 space-y-6 flex-1">
            @if (session('status'))
                <div class="rounded-lg bg-emerald-500/10 border border-emerald-500/40 px-4 py-3 text-sm text-emerald-200 flex items-center justify-between">
                    <span>{{ session('status') }}</span>
                    <button onclick="this.parentElement.remove()" class="text-emerald-400 hover:text-white text-xs ml-4">&times;</button>
                </div>
            @endif

            @if ($errors->any())
                <div class="rounded-lg bg-rose-500/10 border border-rose-500/40 px-4 py-3 text-sm text-rose-200">
                    <div class="font-semibold mb-1">Action could not be completed:</div>
                    <ul class="list-disc list-inside space-y-0.5 text-xs">
                        @foreach ($errors->all() as $err)
                            <li>{{ $err }}</li>
                        @endforeach
                    </ul>
                </div>
            @endif

            @yield('content')
        </div>
    </main>

    <!-- Global Event Detail Modal -->
    <div id="event-detail-modal" class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 hidden items-center justify-center p-4">
        <div class="bg-slate-900 border border-slate-700 rounded-xl max-w-3xl w-full overflow-hidden shadow-2xl">
            <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
                <h3 class="font-bold text-white text-sm">Syslog Event Inspection</h3>
                <button onclick="closeEventModal()" class="text-slate-400 hover:text-white text-lg leading-none">&times;</button>
            </div>
            <div id="event-detail-body" class="p-6 space-y-4 text-xs max-h-[80vh] overflow-y-auto">
                <div class="text-slate-400">Loading event metadata...</div>
            </div>
        </div>
    </div>

    <script>
        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        function severityBadgeHtml(sevNum, sevText) {
            const n = parseInt(sevNum, 10);
            const label = escapeHtml((sevText || 'info').toUpperCase());
            if (n <= 2) return `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">${label}</span>`;
            if (n === 3) return `<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-orange-500/20 text-orange-300 border border-orange-500/40">${label}</span>`;
            if (n === 4) return `<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40">${label}</span>`;
            if (n === 5) return `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">${label}</span>`;
            if (n === 6) return `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">${label}</span>`;
            return `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-700 text-slate-300 border border-slate-600">${label}</span>`;
        }

        async function inspectEvent(id) {
            const modal = document.getElementById('event-detail-modal');
            const body = document.getElementById('event-detail-body');
            modal.classList.remove('hidden');
            modal.classList.add('flex');
            body.innerHTML = '<div class="text-cyan-400 animate-pulse">Loading parsed fields and raw RFC payload...</div>';

            try {
                const resp = await fetch(`/api/logs/${encodeURIComponent(id)}`, {
                    headers: { 'Accept': 'application/json' }
                });
                if (!resp.ok) throw new Error('Failed to load event');
                const data = await resp.json();
                const ev = data.event;
                body.innerHTML = `
                    <div class="grid grid-cols-2 md:grid-cols-3 gap-3 bg-slate-950 p-4 rounded-lg border border-slate-800">
                        <div><div class="text-slate-500">Event ID</div><div class="font-mono text-white mt-0.5">#${escapeHtml(ev.id)}</div></div>
                        <div><div class="text-slate-500">Received At (UTC)</div><div class="font-mono text-white mt-0.5">${escapeHtml(ev.received_at)}</div></div>
                        <div><div class="text-slate-500">Reported At</div><div class="font-mono text-white mt-0.5">${escapeHtml(ev.reported_at)}</div></div>
                        <div><div class="text-slate-500">Hostname</div><div class="font-mono text-cyan-300 mt-0.5">${escapeHtml(ev.hostname)}</div></div>
                        <div><div class="text-slate-500">Source IP</div><div class="font-mono text-cyan-300 mt-0.5">${escapeHtml(ev.source_ip)}</div></div>
                        <div><div class="text-slate-500">Transport</div><div class="font-mono text-white mt-0.5">${escapeHtml(ev.protocol)}</div></div>
                        <div><div class="text-slate-500">Facility</div><div class="font-mono text-white mt-0.5">${escapeHtml(ev.facility)} (${escapeHtml(ev.facility_num)})</div></div>
                        <div><div class="text-slate-500">Severity</div><div class="mt-0.5">${severityBadgeHtml(ev.severity_num, ev.severity)}</div></div>
                        <div><div class="text-slate-500">Application / PID</div><div class="font-mono text-white mt-0.5">${escapeHtml(ev.app_name)} [${escapeHtml(ev.proc_id)}]</div></div>
                        <div><div class="text-slate-500">Classification</div><div class="font-mono text-amber-300 mt-0.5">${escapeHtml(ev.event_category)}</div></div>
                        <div class="col-span-2"><div class="text-slate-500">Disk Archive File</div><div class="font-mono text-slate-300 mt-0.5 break-all">${escapeHtml(ev.archive_file)}</div></div>
                    </div>
                    <div>
                        <div class="text-slate-400 font-semibold mb-1">Sanitized Parsed Message</div>
                        <pre class="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-slate-100 whitespace-pre-wrap break-all">${escapeHtml(ev.message)}</pre>
                    </div>
                    <div>
                        <div class="text-slate-400 font-semibold mb-1">Original Raw Syslog Payload (Preserved for Forensics)</div>
                        <pre class="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-amber-200/90 whitespace-pre-wrap break-all">${escapeHtml(ev.raw_message)}</pre>
                    </div>
                `;
            } catch (e) {
                body.innerHTML = `<div class="text-rose-400">Error loading event details: ${escapeHtml(e.message)}</div>`;
            }
        }

        function closeEventModal() {
            const modal = document.getElementById('event-detail-modal');
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
    </script>
    @stack('scripts')
</body>
</html>
