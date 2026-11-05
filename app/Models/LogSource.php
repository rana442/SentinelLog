<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class LogSource extends Model
{
    protected $fillable = [
        'name',
        'hostname',
        'ip_address',
        'os_type',
        'environment',
        'location',
        'owner',
        'description',
        'is_enabled',
        'heartbeat_threshold_minutes',
        'last_seen_at',
        'last_protocol',
        'events_5m',
        'events_24h',
        'total_events',
        'alert_on_silent',
        'silent_alerted_at',
    ];

    protected function casts(): array
    {
        return [
            'is_enabled' => 'boolean',
            'alert_on_silent' => 'boolean',
            'last_seen_at' => 'datetime',
            'silent_alerted_at' => 'datetime',
        ];
    }

    /**
     * Determine health strictly from recent event timestamps and configurable heartbeat threshold.
     * Never claim a source is Online solely because it exists in the database.
     */
    public function healthStatus(): string
    {
        if (!$this->last_seen_at) {
            return 'Unknown';
        }

        $threshold = max(1, (int) $this->heartbeat_threshold_minutes);
        $minutesAgo = $this->last_seen_at->diffInMinutes(now());

        if ($minutesAgo <= $threshold) {
            return 'Online';
        }
        if ($minutesAgo <= ($threshold * 2)) {
            return 'Delayed';
        }
        return 'Offline';
    }

    public function healthBadgeColor(): string
    {
        return match ($this->healthStatus()) {
            'Online' => 'emerald',
            'Delayed' => 'amber',
            'Offline' => 'rose',
            default => 'slate',
        };
    }
}
