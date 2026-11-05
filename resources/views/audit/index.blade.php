@extends('layouts.app')
@section('title', 'Application Audit Trail')
@section('heading', 'Immutable Application Audit Trail')
@section('subheading', 'Tamper-evident SHA-256 hash-chained log of portal logins, searches, exports, and administrative actions')

@section('content')
<div class="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 text-xs">
    <form method="GET" action="{{ route('audit.index') }}" class="flex flex-wrap items-center gap-2">
        <input type="text" name="action" value="{{ $actionFilter }}" placeholder="Filter action (e.g. auth.login, logs.export)..."
            class="rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-white font-mono">
        <input type="text" name="actor" value="{{ $actorFilter }}" placeholder="Filter actor email or IP..."
            class="rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-white font-mono">
        <button type="submit" class="px-3 py-1.5 rounded-lg bg-cyan-500 text-slate-950 font-bold">Filter Audit Trail</button>
        <a href="{{ route('audit.index') }}" class="px-2.5 py-1.5 rounded-lg bg-slate-800 text-slate-300">Clear</a>
    </form>
    <div class="font-mono text-emerald-400">
        {{ number_format($totalRecords) }} Immutable Chained Records
    </div>
</div>

<div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
    <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
            <thead class="bg-slate-950 text-slate-400 uppercase text-[11px]">
                <tr>
                    <th class="px-4 py-3">ID</th>
                    <th class="px-4 py-3">Timestamp (UTC)</th>
                    <th class="px-4 py-3">Actor / Role</th>
                    <th class="px-4 py-3">Action</th>
                    <th class="px-4 py-3">Object / Target</th>
                    <th class="px-4 py-3">Source IP</th>
                    <th class="px-4 py-3">Metadata &amp; SHA-256 Chain Hash</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/80 font-mono">
                @forelse($logs as $log)
                    <tr class="hover:bg-slate-800/50">
                        <td class="px-4 py-2.5 text-slate-500">#{{ $log->id }}</td>
                        <td class="px-4 py-2.5 whitespace-nowrap text-slate-300">{{ $log->created_at?->format('Y-m-d H:i:s') }}</td>
                        <td class="px-4 py-2.5 whitespace-nowrap">
                            <span class="text-white">{{ $log->actor_name }}</span>
                            <span class="text-slate-500">({{ $log->actor_role }})</span>
                        </td>
                        <td class="px-4 py-2.5 whitespace-nowrap">
                            <span class="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 text-[11px]">
                                {{ $log->action }}
                            </span>
                        </td>
                        <td class="px-4 py-2.5 whitespace-nowrap text-slate-300">{{ $log->target_type }}:{{ $log->target_id ?: '-' }}</td>
                        <td class="px-4 py-2.5 whitespace-nowrap text-amber-300">{{ $log->ip_address }}</td>
                        <td class="px-4 py-2.5 text-[11px] text-slate-400 max-w-xl truncate">
                            <div>{{ json_encode($log->metadata) }}</div>
                            <div class="text-[10px] text-slate-500">sha256: {{ substr($log->integrity_hash, 0, 24) }}...</div>
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="7" class="px-6 py-8 text-center text-slate-500 font-sans">No audit trail records found.</td>
                    </tr>
                @endforelse
            </tbody>
        </table>
    </div>
    <div class="p-4 border-t border-slate-800">
        {{ $logs->links() }}
    </div>
</div>
@endsection
