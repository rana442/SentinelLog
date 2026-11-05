<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class AlertIncident extends Model
{
    protected $fillable = [
        'alert_rule_id',
        'dedup_key',
        'severity',
        'title',
        'summary',
        'source_host',
        'source_ip',
        'match_count',
        'sample_payload',
        'status',
        'notified_channels',
        'acknowledged_by',
        'acknowledged_at',
        'triggered_at',
    ];

    protected function casts(): array
    {
        return [
            'sample_payload' => 'array',
            'notified_channels' => 'array',
            'acknowledged_at' => 'datetime',
            'triggered_at' => 'datetime',
        ];
    }

    public function rule()
    {
        return $this->belongsTo(AlertRule::class, 'alert_rule_id');
    }

    public function acknowledger()
    {
        return $this->belongsTo(User::class, 'acknowledged_by');
    }
}
