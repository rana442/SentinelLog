<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use LogicException;

class AuditLog extends Model
{
    public $timestamps = false;

    protected $fillable = [
        'user_id',
        'actor_name',
        'actor_email',
        'actor_role',
        'action',
        'target_type',
        'target_id',
        'ip_address',
        'user_agent',
        'metadata',
        'integrity_hash',
        'created_at',
    ];

    protected function casts(): array
    {
        return [
            'metadata' => 'array',
            'created_at' => 'datetime',
        ];
    }

    protected static function booted(): void
    {
        static::updating(function () {
            throw new LogicException('Application audit trail records are immutable and cannot be modified.');
        });

        static::deleting(function () {
            throw new LogicException('Application audit trail records are immutable and cannot be deleted.');
        });
    }
}
