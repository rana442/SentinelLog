@extends('layouts.app')
@section('title', 'Log Sources & Network ACLs')
@section('heading', 'Log Source Inventory & Network Access Control')
@section('subheading', 'Manage registered Linux servers, network devices, heartbeat thresholds, and authorized rsyslog subnets')

@section('content')
<div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
    <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
        <div>
            <h2 class="text-sm font-bold text-white">Registered Log Sources</h2>
            <p class="text-xs text-slate-400">Health status is computed dynamically from last-seen event timestamp vs. configurable heartbeat window</p>
        </div>
        <span class="text-xs font-mono text-slate-400">{{ $sources->count() }} registered sources</span>
    </div>
    <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
            <thead class="bg-slate-950 text-slate-400 uppercase text-[11px]">
                <tr>
                    <th class="px-4 py-3">Health</th>
                    <th class="px-4 py-3">Hostname / Name</th>
                    <th class="px-4 py-3">IP Address</th>
                    <th class="px-4 py-3">OS / Environment</th>
                    <th class="px-4 py-3">Location / Owner</th>
                    <th class="px-4 py-3">Last Seen (Proto)</th>
                    <th class="px-4 py-3">Vol (5m / 24h / Total)</th>
                    @can('manage-sources')
                        <th class="px-4 py-3 text-right">Actions</th>
                    @endcan
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/80">
                @foreach($sources as $src)
                    @php
                        $status = $src->healthStatus();
                        $badgeClass = match($status) {
                            'Online' => 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
                            'Delayed' => 'bg-amber-500/20 text-amber-300 border-amber-500/40',
                            'Offline' => 'bg-rose-500/20 text-rose-300 border-rose-500/40',
                            default => 'bg-slate-800 text-slate-400 border-slate-700',
                        };
                    @endphp
                    <tr class="hover:bg-slate-800/50">
                        <td class="px-4 py-3 whitespace-nowrap">
                            <span class="px-2 py-0.5 rounded text-[11px] font-bold border {{ $badgeClass }}">
                                {{ strtoupper($status) }}
                            </span>
                            @if(!$src->is_enabled)
                                <span class="ml-1 text-[10px] text-rose-400 font-mono">(DISABLED)</span>
                            @endif
                        </td>
                        <td class="px-4 py-3">
                            <a href="{{ route('logs.explorer', ['hostname' => $src->hostname]) }}" class="font-mono font-bold text-cyan-300 hover:underline">{{ $src->hostname }}</a>
                            <div class="text-[11px] text-slate-400">{{ $src->name }}</div>
                        </td>
                        <td class="px-4 py-3 font-mono text-slate-200">{{ $src->ip_address }}</td>
                        <td class="px-4 py-3">
                            <div class="text-slate-200">{{ $src->os_type }}</div>
                            <div class="text-[11px] text-slate-400">{{ $src->environment }}</div>
                        </td>
                        <td class="px-4 py-3">
                            <div class="text-slate-200">{{ $src->location ?: '-' }}</div>
                            <div class="text-[11px] text-slate-400">{{ $src->owner ?: '-' }}</div>
                        </td>
                        <td class="px-4 py-3 font-mono">
                            @if($src->last_seen_at)
                                <div class="text-slate-200">{{ $src->last_seen_at->diffForHumans() }}</div>
                                <div class="text-[11px] text-slate-500">{{ $src->last_seen_at->format('Y-m-d H:i:s') }} ({{ $src->last_protocol ?: 'UDP' }})</div>
                            @else
                                <span class="text-slate-500">Never received</span>
                            @endif
                        </td>
                        <td class="px-4 py-3 font-mono text-slate-200">
                            <span class="text-cyan-300">{{ number_format($src->events_5m) }}</span> /
                            <span>{{ number_format($src->events_24h) }}</span> /
                            <span class="text-slate-400">{{ number_format($src->total_events) }}</span>
                        </td>
                        @can('manage-sources')
                            <td class="px-4 py-3 text-right whitespace-nowrap space-x-2">
                                <form method="POST" action="{{ route('sources.toggle', $src) }}" class="inline">
                                    @csrf
                                    <button type="submit" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px]">
                                        {{ $src->is_enabled ? 'Disable' : 'Enable' }}
                                    </button>
                                </form>
                                <form method="POST" action="{{ route('sources.destroy', $src) }}" class="inline" onsubmit="return confirm('Remove source {{ $src->hostname }}?')">
                                    @csrf
                                    @method('DELETE')
                                    <button type="submit" class="px-2 py-1 rounded bg-rose-500/15 hover:bg-rose-500/30 text-rose-300 text-[11px]">
                                        Remove
                                    </button>
                                </form>
                            </td>
                        @endcan
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>
</div>

@can('manage-sources')
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h3 class="text-sm font-bold text-white mb-3">Register New Log Source</h3>
        <form method="POST" action="{{ route('sources.store') }}" class="space-y-3 text-xs">
            @csrf
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                    <label class="block text-slate-400 mb-1">Display Name</label>
                    <input type="text" name="name" required placeholder="Web App Server 01" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Syslog Hostname</label>
                    <input type="text" name="hostname" required placeholder="web-prod-01" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Source IPv4/IPv6 Address</label>
                    <input type="text" name="ip_address" required placeholder="10.20.30.40" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Operating System / Device Type</label>
                    <select name="os_type" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                        <option>Ubuntu 24.04 LTS</option>
                        <option>Debian 12</option>
                        <option>AlmaLinux 9</option>
                        <option>Rocky Linux 9</option>
                        <option>RHEL 9</option>
                        <option>Cisco / Juniper Router</option>
                        <option>FortiGate / PaloAlto / pfSense Firewall</option>
                        <option>Managed Switch</option>
                    </select>
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Environment</label>
                    <select name="environment" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                        <option>Production</option>
                        <option>Staging</option>
                        <option>DMZ</option>
                        <option>Core Network</option>
                        <option>Development</option>
                    </select>
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Heartbeat Threshold (Minutes)</label>
                    <input type="number" name="heartbeat_threshold_minutes" value="15" min="1" max="1440" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Location / Rack</label>
                    <input type="text" name="location" placeholder="DC-1 Rack B4" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">System Owner / Team</label>
                    <input type="text" name="owner" placeholder="Linux Infrastructure" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                </div>
            </div>
            <div>
                <label class="block text-slate-400 mb-1">Description</label>
                <input type="text" name="description" placeholder="Optional notes about role and criticality" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
            </div>
            <div class="flex items-center justify-between pt-2">
                <label class="flex items-center space-x-2 text-slate-300">
                    <input type="checkbox" name="alert_on_silent" value="1" checked class="rounded bg-slate-950 border-slate-700">
                    <span>Trigger alert if source stops sending logs</span>
                </label>
                <button type="submit" class="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold">
                    Register &amp; Authorize Source
                </button>
            </div>
        </form>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div>
            <h3 class="text-sm font-bold text-white">Authorized Subnets (rsyslog $AllowedSender ACL)</h3>
            <p class="text-xs text-slate-400">Changes automatically validate with <code class="text-cyan-300">rsyslogd -N1</code> and reload <code class="text-cyan-300">/etc/rsyslog.d/15-allowed-senders.conf</code></p>
        </div>

        <form method="POST" action="{{ route('sources.subnets.store') }}" class="flex flex-wrap gap-2 text-xs">
            @csrf
            <input type="text" name="cidr" required placeholder="e.g. 10.50.0.0/16 or 203.0.113.10" class="flex-1 rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
            <select name="protocol" class="rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                <option value="ANY">UDP &amp; TCP</option>
                <option value="TCP">TCP / TLS</option>
                <option value="UDP">UDP</option>
            </select>
            <input type="text" name="description" placeholder="Subnet description" class="flex-1 rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
            <button type="submit" class="px-3.5 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold">Add CIDR</button>
        </form>

        <div class="space-y-2 max-h-60 overflow-y-auto">
            @foreach($subnets as $sn)
                <div class="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                    <div>
                        <span class="font-mono font-bold text-emerald-300">{{ $sn->cidr }}</span>
                        <span class="ml-2 px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">{{ $sn->protocol }}</span>
                        <div class="text-[11px] text-slate-400 mt-0.5">{{ $sn->description }}</div>
                    </div>
                    <form method="POST" action="{{ route('sources.subnets.destroy', $sn) }}">
                        @csrf
                        @method('DELETE')
                        <button type="submit" class="text-rose-400 hover:underline text-[11px]">Remove</button>
                    </form>
                </div>
            @endforeach
        </div>
    </div>
</div>
@endcan

<div class="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
    <h3 class="text-sm font-bold text-white">Client &amp; Network Appliance Onboarding Configuration</h3>
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
        <div>
            <div class="font-semibold text-cyan-300 mb-1">1. Linux Servers (Ubuntu / Debian / RHEL / Rocky / AlmaLinux) ??? TCP + Disk Queue or TLS 6514</div>
            <pre class="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-slate-200 overflow-x-auto"># /etc/rsyslog.d/90-central-forward.conf
action(
    type="omfwd"
    Target="{{ $serverIp }}"
    Port="514"
    Protocol="tcp"
    queue.type="LinkedList"
    queue.filename="central_fwd_q"
    queue.saveOnShutdown="on"
    action.resumeRetryCount="-1"
)

# For TLS 6514 encrypted transport (install rsyslog-gnutls & copy ca.pem):
# global(defaultNetstreamDriverCAFile="/etc/rsyslog.d/certs/ca.pem")
# action(type="omfwd" Target="{{ $serverIp }}" Port="6514" Protocol="tcp"
#        StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="anon")</pre>
        </div>

        <div>
            <div class="font-semibold text-amber-300 mb-1">2. Network Devices (Cisco IOS-XE, Juniper Junos, FortiGate, MikroTik, pfSense)</div>
            <pre class="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-slate-200 overflow-x-auto">! Cisco IOS / IOS-XE:
logging host {{ $serverIp }} transport udp port 514
logging trap informational
service timestamps log datetime msec show-timezone

# Juniper Junos:
set system syslog host {{ $serverIp }} any info
set system syslog host {{ $serverIp }} port 514

# FortiGate FortiOS CLI:
config log syslogd setting
    set status enable
    set server "{{ $serverIp }}"
    set mode udp
    set port 514
end</pre>
        </div>
    </div>
</div>
@endsection
