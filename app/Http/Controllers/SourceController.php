<?php

namespace App\Http\Controllers;

use App\Models\AuthorizedSubnet;
use App\Models\LogSource;
use App\Services\AuditService;
use App\Services\RsyslogConfigService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class SourceController extends Controller
{
    public function index()
    {
        $sources = LogSource::orderByDesc('last_seen_at')->get();
        $subnets = AuthorizedSubnet::orderBy('cidr')->get();

        return view('sources.index', [
            'sources' => $sources,
            'subnets' => $subnets,
            'serverIp' => '103.72.109.7',
        ]);
    }

    public function store(Request $request)
    {
        Gate::authorize('manage-sources');

        $validated = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'hostname' => ['required', 'string', 'max:190', 'regex:/^[a-zA-Z0-9._\-]+$/'],
            'ip_address' => ['required', 'ip', 'unique:log_sources,ip_address'],
            'os_type' => ['required', 'string', 'max:64'],
            'environment' => ['required', 'string', 'max:64'],
            'location' => ['nullable', 'string', 'max:120'],
            'owner' => ['nullable', 'string', 'max:120'],
            'description' => ['nullable', 'string', 'max:500'],
            'heartbeat_threshold_minutes' => ['required', 'integer', 'min:1', 'max:1440'],
            'alert_on_silent' => ['nullable', 'boolean'],
        ]);

        $validated['is_enabled'] = true;
        $validated['alert_on_silent'] = $request->boolean('alert_on_silent', true);

        $source = LogSource::create($validated);
        RsyslogConfigService::syncAllowedSenders();

        AuditService::record('source.created', 'log_source', (string) $source->id, [
            'hostname' => $source->hostname,
            'ip_address' => $source->ip_address,
        ]);

        return back()->with('status', "Log source '{$source->hostname}' ({$source->ip_address}) registered and authorized.");
    }

    public function update(Request $request, LogSource $source)
    {
        Gate::authorize('manage-sources');

        $validated = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'hostname' => ['required', 'string', 'max:190', 'regex:/^[a-zA-Z0-9._\-]+$/'],
            'ip_address' => ['required', 'ip', 'unique:log_sources,ip_address,' . $source->id],
            'os_type' => ['required', 'string', 'max:64'],
            'environment' => ['required', 'string', 'max:64'],
            'location' => ['nullable', 'string', 'max:120'],
            'owner' => ['nullable', 'string', 'max:120'],
            'description' => ['nullable', 'string', 'max:500'],
            'heartbeat_threshold_minutes' => ['required', 'integer', 'min:1', 'max:1440'],
            'alert_on_silent' => ['nullable', 'boolean'],
        ]);

        $validated['alert_on_silent'] = $request->boolean('alert_on_silent');
        $source->update($validated);
        RsyslogConfigService::syncAllowedSenders();

        AuditService::record('source.updated', 'log_source', (string) $source->id, [
            'hostname' => $source->hostname,
            'ip_address' => $source->ip_address,
        ]);

        return back()->with('status', "Source '{$source->hostname}' updated.");
    }

    public function toggle(LogSource $source)
    {
        Gate::authorize('manage-sources');

        $source->update(['is_enabled' => !$source->is_enabled]);
        RsyslogConfigService::syncAllowedSenders();

        AuditService::record($source->is_enabled ? 'source.enabled' : 'source.disabled', 'log_source', (string) $source->id, [
            'hostname' => $source->hostname,
            'ip_address' => $source->ip_address,
        ]);

        return back()->with('status', "Source '{$source->hostname}' " . ($source->is_enabled ? 'enabled' : 'disabled') . '.');
    }

    public function destroy(LogSource $source)
    {
        Gate::authorize('manage-sources');

        $meta = ['hostname' => $source->hostname, 'ip_address' => $source->ip_address];
        $id = $source->id;
        $source->delete();
        RsyslogConfigService::syncAllowedSenders();

        AuditService::record('source.deleted', 'log_source', (string) $id, $meta);

        return back()->with('status', "Source '{$meta['hostname']}' removed.");
    }

    public function storeSubnet(Request $request)
    {
        Gate::authorize('manage-sources');

        $validated = $request->validate([
            'cidr' => ['required', 'string', 'max:64'],
            'protocol' => ['required', 'in:ANY,UDP,TCP,TLS'],
            'description' => ['nullable', 'string', 'max:255'],
        ]);

        $normalized = RsyslogConfigService::validateCidrOrIp($validated['cidr']);
        if (!$normalized) {
            return back()->withErrors(['cidr' => 'Invalid IPv4 address or CIDR notation (example: 10.20.0.0/16 or 192.168.1.50).']);
        }

        $subnet = AuthorizedSubnet::updateOrCreate(
            ['cidr' => $normalized],
            [
                'protocol' => $validated['protocol'],
                'description' => $validated['description'],
                'is_active' => true,
                'created_by' => $request->user()->id,
            ]
        );

        RsyslogConfigService::syncAllowedSenders();

        AuditService::record('subnet.created', 'authorized_subnet', (string) $subnet->id, [
            'cidr' => $subnet->cidr,
            'protocol' => $subnet->protocol,
        ]);

        return back()->with('status', "Authorized subnet {$subnet->cidr} added and synced with rsyslog.");
    }

    public function destroySubnet(AuthorizedSubnet $subnet)
    {
        Gate::authorize('manage-sources');

        $cidr = $subnet->cidr;
        $id = $subnet->id;
        $subnet->delete();
        RsyslogConfigService::syncAllowedSenders();

        AuditService::record('subnet.deleted', 'authorized_subnet', (string) $id, ['cidr' => $cidr]);

        return back()->with('status', "Authorized subnet {$cidr} removed and synced with rsyslog.");
    }
}
