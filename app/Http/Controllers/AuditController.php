<?php

namespace App\Http\Controllers;

use App\Models\AuditLog;
use Illuminate\Http\Request;

class AuditController extends Controller
{
    public function index(Request $request)
    {
        $actionFilter = trim((string) $request->query('action', ''));
        $actorFilter = trim((string) $request->query('actor', ''));

        $query = AuditLog::orderByDesc('id');
        if ($actionFilter !== '') {
            $query->where('action', 'like', "%{$actionFilter}%");
        }
        if ($actorFilter !== '') {
            $query->where(function ($q) use ($actorFilter) {
                $q->where('actor_email', 'like', "%{$actorFilter}%")
                  ->orWhere('actor_name', 'like', "%{$actorFilter}%")
                  ->orWhere('ip_address', 'like', "%{$actorFilter}%");
            });
        }

        $logs = $query->paginate(30)->withQueryString();
        $totalRecords = AuditLog::count();

        return view('audit.index', [
            'logs' => $logs,
            'actionFilter' => $actionFilter,
            'actorFilter' => $actorFilter,
            'totalRecords' => $totalRecords,
        ]);
    }
}
