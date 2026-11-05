@extends('layouts.app')
@section('title', 'Log Explorer & FTS5 Search')
@section('heading', 'Log Explorer & Incident Investigation')
@section('subheading', 'Full-text indexed search (SQLite FTS5), multi-attribute filtering, investigation pinning, and audited CSV export')

@section('content')
<div class="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
    <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex flex-wrap items-center gap-1.5 text-xs">
            <span class="text-slate-400 font-medium mr-1">Quick Filters:</span>
            @php
                $quickFilters = [
                    '' => 'All Logs',
                    'auth_failure' => 'Auth Failures',
                    'ssh_auth' => 'SSH Activity',
                    'sudo' => 'Sudo Activity',
                    'kernel' => 'Kernel Events',
                    'service_failure' => 'Service Failures',
                    'firewall' => 'Firewall Blocks',
                    'critical_only' => 'Critical / Emergency',
                    'pinned' => 'Pinned Investigations',
                ];
            @endphp
            @foreach($quickFilters as $qfKey => $qfLabel)
                <a href="{{ route('logs.explorer', array_merge($filters, ['quick_filter' => $qfKey, 'page' => 1])) }}"
                   class="px-2.5 py-1 rounded-lg border transition {{ ($filters['quick_filter'] ?? '') === $qfKey ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-semibold' : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700' }}">
                    {{ $qfLabel }}
                </a>
            @endforeach
        </div>

        @can('export-logs')
            <a href="{{ route('logs.export.csv', $filters) }}" class="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-xs font-semibold">
                Export Matching CSV (Audited)
            </a>
        @endcan
    </div>

    @if($savedSearches->count() > 0)
        <div class="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/80 text-xs">
            <span class="text-slate-400">Saved Searches:</span>
            @foreach($savedSearches as $ss)
                <div class="inline-flex items-center rounded-md bg-slate-950 border border-slate-800">
                    <a href="{{ route('logs.explorer', $ss->filters) }}" class="px-2.5 py-1 text-cyan-300 hover:underline">
                        {{ $ss->name }}
                    </a>
                    @if($ss->user_id === auth()->id() || auth()->user()->isAdminOrAbove())
                        <form method="POST" action="{{ route('logs.searches.destroy', $ss) }}" class="inline">
                            @csrf
                            @method('DELETE')
                            <button type="submit" class="px-1.5 py-1 text-slate-500 hover:text-rose-400">&times;</button>
                        </form>
                    @endif
                </div>
            @endforeach
        </div>
    @endif
</div>

<form method="GET" action="{{ route('logs.explorer') }}" class="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 text-xs">
    <input type="hidden" name="quick_filter" value="{{ $filters['quick_filter'] ?? '' }}">

    <div class="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div class="md:col-span-2">
            <label class="block text-slate-400 mb-1">Full-Text Search (Message, Raw Payload, Host, App)</label>
            <input type="text" name="q" value="{{ $filters['q'] ?? '' }}" placeholder="e.g. Failed password, UFW BLOCK, segfault, root..."
                class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white focus:border-cyan-500 focus:outline-none">
        </div>

        <div>
            <label class="block text-slate-400 mb-1">Source Hostname</label>
            <select name="hostname" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                <option value="">All Hostnames</option>
                @foreach($facets['hosts'] as $h)
                    <option value="{{ $h }}" @selected(($filters['hostname'] ?? '') === $h)>{{ $h }}</option>
                @endforeach
            </select>
        </div>

        <div>
            <label class="block text-slate-400 mb-1">Source IP Address</label>
            <select name="source_ip" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                <option value="">All Source IPs</option>
                @foreach($facets['ips'] as $ip)
                    <option value="{{ $ip }}" @selected(($filters['source_ip'] ?? '') === $ip)>{{ $ip }}</option>
                @endforeach
            </select>
        </div>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-6 gap-3">
        <div>
            <label class="block text-slate-400 mb-1">Exact Severity</label>
            <select name="severity" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                <option value="">Any Severity</option>
                @foreach(config('syslog.severities') as $num => $meta)
                    <option value="{{ $num }}" @selected((string)($filters['severity'] ?? '') === (string)$num)>{{ $num }} - {{ $meta['label'] }}</option>
                @endforeach
            </select>
        </div>

        <div>
            <label class="block text-slate-400 mb-1">Facility</label>
            <select name="facility" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                <option value="">Any Facility</option>
                @foreach($facets['facilities'] as $fac)
                    <option value="{{ $fac }}" @selected(($filters['facility'] ?? '') === $fac)>{{ $fac }}</option>
                @endforeach
            </select>
        </div>

        <div>
            <label class="block text-slate-400 mb-1">Application / Program</label>
            <select name="app_name" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                <option value="">Any Application</option>
                @foreach($facets['apps'] as $app)
                    <option value="{{ $app }}" @selected(($filters['app_name'] ?? '') === $app)>{{ $app }}</option>
                @endforeach
            </select>
        </div>

        <div>
            <label class="block text-slate-400 mb-1">Transport</label>
            <select name="protocol" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                <option value="">All (UDP/TCP/TLS)</option>
                @foreach(['UDP', 'TCP', 'TLS', 'LOCAL'] as $p)
                    <option value="{{ $p }}" @selected(($filters['protocol'] ?? '') === $p)>{{ $p }}</option>
                @endforeach
            </select>
        </div>

        <div>
            <label class="block text-slate-400 mb-1">From Date/Time (UTC)</label>
            <input type="datetime-local" name="date_from" value="{{ $filters['date_from'] ?? '' }}"
                class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2.5 py-2 text-white">
        </div>

        <div>
            <label class="block text-slate-400 mb-1">To Date/Time (UTC)</label>
            <input type="datetime-local" name="date_to" value="{{ $filters['date_to'] ?? '' }}"
                class="w-full rounded-lg bg-slate-950 border border-slate-700 px-2.5 py-2 text-white">
        </div>
    </div>

    <div class="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800">
        <div class="flex items-center space-x-3">
            <label class="text-slate-400">Page Size:</label>
            <select name="per_page" class="rounded bg-slate-950 border border-slate-700 px-2 py-1 text-white">
                @foreach([25, 50, 100, 200] as $sz)
                    <option value="{{ $sz }}" @selected($perPage === $sz)>{{ $sz }} rows</option>
                @endforeach
            </select>

            <label class="text-slate-400">Order:</label>
            <select name="sort" class="rounded bg-slate-950 border border-slate-700 px-2 py-1 text-white">
                <option value="DESC" @selected($sortDir === 'DESC')>Newest First</option>
                <option value="ASC" @selected($sortDir === 'ASC')>Oldest First</option>
            </select>
        </div>

        <div class="flex items-center space-x-2">
            <a href="{{ route('logs.explorer') }}" class="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300">Reset Filters</a>
            <button type="submit" class="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold">
                Search Logs
            </button>
        </div>
    </div>
</form>

<div class="flex flex-wrap items-center justify-between gap-3 text-xs">
    <div class="text-slate-400">
        Showing <span class="text-white font-bold font-mono">{{ count($results['items']) }}</span> of
        <span class="text-cyan-300 font-bold font-mono">{{ number_format($results['total']) }}</span> matching events
        (Page {{ $results['current_page'] }} of {{ $results['last_page'] }})
    </div>

    <form method="POST" action="{{ route('logs.searches.store') }}" class="flex items-center gap-2">
        @csrf
        @foreach($filters as $fk => $fv)
            @if($fv !== '' && $fv !== null)
                <input type="hidden" name="filters[{{ $fk }}]" value="{{ $fv }}">
            @endif
        @endforeach
        <input type="text" name="name" required placeholder="Save current filter as..."
            class="rounded-lg bg-slate-900 border border-slate-700 px-3 py-1.5 text-white">
        @if(auth()->user()->isAnalystOrAbove())
            <label class="flex items-center gap-1 text-slate-400">
                <input type="checkbox" name="is_shared" value="1" class="rounded bg-slate-950 border-slate-700">
                <span>Share</span>
            </label>
        @endif
        <button type="submit" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 font-medium">
            Save Filter
        </button>
    </form>
</div>

<div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
    <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
            <thead class="bg-slate-950 text-slate-400 uppercase text-[11px]">
                <tr>
                    <th class="px-4 py-3">ID</th>
                    <th class="px-4 py-3">Timestamp (UTC)</th>
                    <th class="px-4 py-3">Severity</th>
                    <th class="px-4 py-3">Proto</th>
                    <th class="px-4 py-3">Host / Source IP</th>
                    <th class="px-4 py-3">Facility / App</th>
                    <th class="px-4 py-3">Message (Sanitized)</th>
                    <th class="px-4 py-3 text-right">Actions</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/80 font-mono">
                @forelse($results['items'] as $ev)
                    @php
                        $sevNum = (int)$ev['severity_num'];
                        $sevClass = match(true) {
                            $sevNum <= 2 => 'bg-rose-500/20 text-rose-300 border-rose-500/40',
                            $sevNum === 3 => 'bg-orange-500/20 text-orange-300 border-orange-500/40',
                            $sevNum === 4 => 'bg-amber-500/20 text-amber-300 border-amber-500/40',
                            $sevNum === 5 => 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
                            $sevNum === 6 => 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
                            default => 'bg-slate-800 text-slate-300 border-slate-700',
                        };
                    @endphp
                    <tr class="hover:bg-slate-800/60 transition {{ (int)$ev['is_pinned'] === 1 ? 'bg-amber-500/5' : '' }}">
                        <td onclick="inspectEvent({{ (int)$ev['id'] }})" class="px-4 py-2.5 text-slate-500 cursor-pointer whitespace-nowrap">
                            #{{ $ev['id'] }}
                            @if((int)$ev['is_pinned'] === 1)
                                <span class="text-amber-400 font-bold" title="Pinned for active investigation">[PIN]</span>
                            @endif
                        </td>
                        <td onclick="inspectEvent({{ (int)$ev['id'] }})" class="px-4 py-2.5 whitespace-nowrap text-slate-300 cursor-pointer">{{ $ev['received_at'] }}</td>
                        <td onclick="inspectEvent({{ (int)$ev['id'] }})" class="px-4 py-2.5 whitespace-nowrap cursor-pointer">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold border {{ $sevClass }}">
                                {{ strtoupper($ev['severity']) }}
                            </span>
                        </td>
                        <td onclick="inspectEvent({{ (int)$ev['id'] }})" class="px-4 py-2.5 whitespace-nowrap text-slate-400 cursor-pointer">{{ $ev['protocol'] }}</td>
                        <td onclick="inspectEvent({{ (int)$ev['id'] }})" class="px-4 py-2.5 whitespace-nowrap text-cyan-300 cursor-pointer">
                            {{ $ev['hostname'] }} <span class="text-slate-500">({{ $ev['source_ip'] }})</span>
                        </td>
                        <td onclick="inspectEvent({{ (int)$ev['id'] }})" class="px-4 py-2.5 whitespace-nowrap text-slate-300 cursor-pointer">
                            {{ $ev['facility'] }}/{{ $ev['app_name'] }}
                        </td>
                        <td onclick="inspectEvent({{ (int)$ev['id'] }})" class="px-4 py-2.5 text-slate-100 max-w-xl truncate cursor-pointer">
                            {{ $ev['message'] }}
                        </td>
                        <td class="px-4 py-2.5 whitespace-nowrap text-right font-sans">
                            <button type="button" onclick="inspectEvent({{ (int)$ev['id'] }})" class="text-cyan-400 hover:underline mr-2">Raw</button>
                            @can('investigate-logs')
                                <form method="POST" action="{{ route('logs.pin', (int)$ev['id']) }}" class="inline">
                                    @csrf
                                    <button type="submit" class="text-[11px] {{ (int)$ev['is_pinned'] === 1 ? 'text-amber-400 font-bold' : 'text-slate-400 hover:text-amber-300' }}">
                                        {{ (int)$ev['is_pinned'] === 1 ? 'Unpin' : 'Pin' }}
                                    </button>
                                </form>
                            @endcan
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="8" class="px-6 py-10 text-center text-slate-500 font-sans">
                            No syslog events matched the current search criteria. Try broadening your date range or clearing filters.
                        </td>
                    </tr>
                @endforelse
            </tbody>
        </table>
    </div>

    @if($results['last_page'] > 1)
        <div class="px-6 py-3 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-xs">
            <div>Page {{ $results['current_page'] }} of {{ $results['last_page'] }}</div>
            <div class="flex items-center space-x-2">
                @if($results['current_page'] > 1)
                    <a href="{{ route('logs.explorer', array_merge($filters, ['per_page' => $perPage, 'sort' => $sortDir, 'page' => $results['current_page'] - 1])) }}"
                       class="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200">&larr; Previous</a>
                @endif
                @if($results['current_page'] < $results['last_page'])
                    <a href="{{ route('logs.explorer', array_merge($filters, ['per_page' => $perPage, 'sort' => $sortDir, 'page' => $results['current_page'] + 1])) }}"
                       class="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200">Next &rarr;</a>
                @endif
            </div>
        </div>
    @endif
</div>
@endsection
