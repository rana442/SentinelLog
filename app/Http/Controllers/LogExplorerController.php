<?php

namespace App\Http\Controllers;

use App\Models\SavedSearch;
use App\Models\SystemSetting;
use App\Services\AuditService;
use App\Services\SyslogIndexService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\StreamedResponse;

class LogExplorerController extends Controller
{
    public function index(Request $request, SyslogIndexService $index)
    {
        $filters = $this->extractFilters($request);
        $perPage = max(10, min(200, (int) $request->query('per_page', 50)));
        $page = max(1, (int) $request->query('page', 1));
        $sortDir = strtoupper((string) $request->query('sort', 'DESC')) === 'ASC' ? 'ASC' : 'DESC';

        $results = $index->search($filters, $perPage, $page, $sortDir);
        $facets = $index->getFacetOptions();

        if (!empty(array_filter($filters))) {
            AuditService::record('logs.search', 'syslog_events', null, [
                'filters' => array_filter($filters),
                'total_matches' => $results['total'],
            ]);
        }

        $savedSearches = SavedSearch::where('user_id', $request->user()->id)
            ->orWhere('is_shared', true)
            ->orderBy('name')
            ->get();

        $timezone = $request->query('tz') ?: ($request->user()?->timezone ?: SystemSetting::getValue('default_timezone', 'UTC'));

        return view('logs.explorer', [
            'results' => $results,
            'filters' => $filters,
            'facets' => $facets,
            'savedSearches' => $savedSearches,
            'perPage' => $perPage,
            'sortDir' => $sortDir,
            'displayTimezone' => $timezone,
        ]);
    }

    public function show(int $id, SyslogIndexService $index)
    {
        $event = $index->findEvent($id);
        if (!$event) {
            return response()->json(['error' => 'Event not found'], 404);
        }

        return response()->json(['event' => $event]);
    }

    public function togglePin(int $id, SyslogIndexService $index)
    {
        Gate::authorize('investigate-logs');

        $event = $index->togglePin($id);
        if (!$event) {
            abort(404, 'Syslog event not found.');
        }

        AuditService::record(
            $event['is_pinned'] ? 'logs.pinned_for_investigation' : 'logs.unpinned',
            'syslog_event',
            (string) $id,
            ['hostname' => $event['hostname'], 'source_ip' => $event['source_ip']]
        );

        return back()->with('status', $event['is_pinned']
            ? "Event #{$id} pinned for active investigation (protected from automated retention deletion)."
            : "Event #{$id} unpinned."
        );
    }

    public function saveSearch(Request $request)
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:100'],
            'is_shared' => ['nullable', 'boolean'],
            'filters' => ['required', 'array'],
        ]);

        $saved = SavedSearch::create([
            'user_id' => $request->user()->id,
            'name' => $validated['name'],
            'is_shared' => $request->boolean('is_shared') && $request->user()->isAnalystOrAbove(),
            'filters' => array_only_valid($validated['filters']),
        ]);

        AuditService::record('logs.saved_search_created', 'saved_search', (string) $saved->id, [
            'name' => $saved->name,
        ]);

        return back()->with('status', "Saved search '{$saved->name}' created.");
    }

    public function deleteSearch(Request $request, SavedSearch $search)
    {
        if ($search->user_id !== $request->user()->id && !$request->user()->isAdminOrAbove()) {
            abort(403);
        }

        $name = $search->name;
        $search->delete();
        AuditService::record('logs.saved_search_deleted', 'saved_search', (string) $search->id, ['name' => $name]);

        return back()->with('status', "Saved search '{$name}' removed.");
    }

    public function exportCsv(Request $request, SyslogIndexService $index): StreamedResponse
    {
        Gate::authorize('export-logs');

        $filters = $this->extractFilters($request);
        $results = $index->search($filters, 250, 1, 'DESC');
        $rows = $results['items'];

        AuditService::record('logs.export_csv', 'syslog_events', null, [
            'filters' => array_filter($filters),
            'exported_count' => count($rows),
        ]);

        $filename = 'syslog-export-' . now()->utc()->format('Ymd-His') . '.csv';

        return response()->streamDownload(function () use ($rows) {
            $out = fopen('php://output', 'w');
            fputcsv($out, [
                'Event ID', 'Received At (UTC)', 'Reported At (UTC)', 'Source IP', 'Hostname',
                'Protocol', 'Facility', 'Severity', 'Application', 'Proc ID', 'Category', 'Message', 'Raw Message'
            ]);

            foreach ($rows as $r) {
                fputcsv($out, [
                    $r['id'],
                    $r['received_at'],
                    $r['reported_at'],
                    self::escapeCsvCell($r['source_ip']),
                    self::escapeCsvCell($r['hostname']),
                    $r['protocol'],
                    $r['facility'],
                    $r['severity'],
                    self::escapeCsvCell($r['app_name']),
                    self::escapeCsvCell((string) $r['proc_id']),
                    $r['event_category'],
                    self::escapeCsvCell($r['message']),
                    self::escapeCsvCell($r['raw_message']),
                ]);
            }
            fclose($out);
        }, $filename, [
            'Content-Type' => 'text/csv; charset=UTF-8',
        ]);
    }

    protected static function escapeCsvCell(string $value): string
    {
        if ($value !== '' && in_array($value[0], ['=', '+', '-', '@', "\t", "\r"], true)) {
            return "'" . $value;
        }
        return $value;
    }

    protected function extractFilters(Request $request): array
    {
        return [
            'q' => substr(trim((string) $request->query('q', '')), 0, 200),
            'hostname' => substr(trim((string) $request->query('hostname', '')), 0, 190),
            'source_ip' => substr(trim((string) $request->query('source_ip', '')), 0, 45),
            'severity' => $request->query('severity', ''),
            'max_severity' => $request->query('max_severity', ''),
            'facility' => substr(trim((string) $request->query('facility', '')), 0, 32),
            'app_name' => substr(trim((string) $request->query('app_name', '')), 0, 96),
            'protocol' => substr(trim((string) $request->query('protocol', '')), 0, 16),
            'quick_filter' => substr(trim((string) $request->query('quick_filter', '')), 0, 32),
            'date_from' => substr(trim((string) $request->query('date_from', '')), 0, 32),
            'date_to' => substr(trim((string) $request->query('date_to', '')), 0, 32),
        ];
    }
}

if (!function_exists('array_only_valid')) {
    function array_only_valid(array $input): array
    {
        $allowed = ['q', 'hostname', 'source_ip', 'severity', 'max_severity', 'facility', 'app_name', 'protocol', 'quick_filter', 'date_from', 'date_to'];
        return array_filter(
            array_intersect_key($input, array_flip($allowed)),
            fn($v) => $v !== null && $v !== ''
        );
    }
}
