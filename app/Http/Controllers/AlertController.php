<?php

namespace App\Http\Controllers;

use App\Models\AlertIncident;
use App\Models\AlertRule;
use App\Services\AlertEngineService;
use App\Services\AuditService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class AlertController extends Controller
{
    public function index(Request $request)
    {
        $statusFilter = $request->query('status', '');
        $incQuery = AlertIncident::with(['rule', 'acknowledger'])->orderByDesc('triggered_at');
        if ($statusFilter !== '') {
            $incQuery->where('status', $statusFilter);
        }

        $incidents = $incQuery->paginate(25)->withQueryString();
        $rules = AlertRule::orderBy('id')->get();

        return view('alerts.index', [
            'incidents' => $incidents,
            'rules' => $rules,
            'statusFilter' => $statusFilter,
        ]);
    }

    public function storeRule(Request $request)
    {
        Gate::authorize('manage-settings');

        $validated = $request->validate([
            'name' => ['required', 'string', 'max:150'],
            'rule_type' => ['required', 'in:auth_failure,ssh_bruteforce,critical_severity,service_failure,disk_usage,volume_spike,silent_source,custom_pattern'],
            'pattern' => ['nullable', 'string', 'max:255'],
            'severity_threshold' => ['nullable', 'integer', 'min:0', 'max:7'],
            'threshold_count' => ['required', 'integer', 'min:1', 'max:1000000'],
            'window_minutes' => ['required', 'integer', 'min:1', 'max:1440'],
            'cooldown_minutes' => ['required', 'integer', 'min:1', 'max:1440'],
            'channels' => ['required', 'array', 'min:1'],
            'channels.*' => ['in:email,telegram'],
            'recipients' => ['nullable', 'string', 'max:255'],
        ]);

        $validated['is_enabled'] = true;
        $rule = AlertRule::create($validated);

        AuditService::record('alert_rule.created', 'alert_rule', (string) $rule->id, [
            'name' => $rule->name,
            'rule_type' => $rule->rule_type,
        ]);

        return back()->with('status', "Alert rule '{$rule->name}' created.");
    }

    public function toggleRule(AlertRule $rule)
    {
        Gate::authorize('manage-settings');

        $rule->update(['is_enabled' => !$rule->is_enabled]);

        AuditService::record($rule->is_enabled ? 'alert_rule.enabled' : 'alert_rule.disabled', 'alert_rule', (string) $rule->id, [
            'name' => $rule->name,
        ]);

        return back()->with('status', "Alert rule '{$rule->name}' " . ($rule->is_enabled ? 'enabled' : 'disabled') . '.');
    }

    public function destroyRule(AlertRule $rule)
    {
        Gate::authorize('manage-settings');

        $name = $rule->name;
        $id = $rule->id;
        $rule->delete();

        AuditService::record('alert_rule.deleted', 'alert_rule', (string) $id, ['name' => $name]);

        return back()->with('status', "Alert rule '{$name}' deleted.");
    }

    public function updateIncidentStatus(Request $request, AlertIncident $incident)
    {
        Gate::authorize('investigate-logs');

        $validated = $request->validate([
            'status' => ['required', 'in:acknowledged,resolved'],
        ]);

        $incident->update([
            'status' => $validated['status'],
            'acknowledged_by' => $request->user()->id,
            'acknowledged_at' => now(),
        ]);

        AuditService::record("alert_incident.{$validated['status']}", 'alert_incident', (string) $incident->id, [
            'title' => $incident->title,
        ]);

        return back()->with('status', "Incident #{$incident->id} marked as {$validated['status']}.");
    }

    public function evaluateNow(AlertEngineService $engine)
    {
        Gate::authorize('investigate-logs');

        $fired = $engine->evaluateAll();
        AuditService::record('alert_engine.manual_run', 'system', 'alerts', ['incidents_triggered' => $fired]);

        return back()->with('status', "Alert evaluation completed ({$fired} new incident(s) triggered).");
    }
}
