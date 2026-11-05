<?php

namespace App\Http\Controllers;

use App\Models\SystemSetting;
use App\Services\SyslogIndexService;
use Illuminate\Http\Request;

class LiveLogController extends Controller
{
    public function index(Request $request, SyslogIndexService $index)
    {
        $facets = $index->getFacetOptions();
        $events = $index->getRecentEvents(0, 50);
        $timezone = $request->user()?->timezone ?: SystemSetting::getValue('default_timezone', 'UTC');

        return view('logs.live', [
            'initialEvents' => $events,
            'facets' => $facets,
            'displayTimezone' => $timezone,
        ]);
    }

    public function poll(Request $request, SyslogIndexService $index)
    {
        $afterId = max(0, (int) $request->query('after_id', 0));
        $filters = [
            'hostname' => $request->query('hostname'),
            'max_severity' => $request->query('max_severity'),
            'protocol' => $request->query('protocol'),
        ];

        $events = $index->getRecentEvents($afterId, 50, $filters);

        return response()->json([
            'events' => $events,
            'server_time_utc' => now()->utc()->toIso8601String(),
        ]);
    }
}
