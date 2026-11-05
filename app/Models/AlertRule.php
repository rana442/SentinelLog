<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class AlertRule extends Model
{
    protected $fillable = [
        'name',
        'rule_type',
        'pattern',
        'severity_threshold',
        'threshold_count',
        'window_minutes',
        'cooldown_minutes',
        'channels',
        'recipients',
        'is_enabled',
        'last_triggered_at',
    ];

    protected function casts(): array
    {
        return [
            'is_enabled' => 'boolean',
            'channels' => 'array',
            'last_triggered_at' => 'datetime',
        ];
    }

    public function incidents()
    {
        return $this->hasMany(AlertIncident::class);
    }
}
