<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    use HasFactory, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
        'role',
        'is_active',
        'timezone',
        'last_login_at',
        'last_login_ip',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'last_login_at' => 'datetime',
            'password' => 'hashed',
            'is_active' => 'boolean',
        ];
    }

    public function roleLabel(): string
    {
        return config('syslog.roles.' . $this->role, ucfirst(str_replace('_', ' ', $this->role)));
    }

    public function isSuperAdmin(): bool
    {
        return $this->is_active && $this->role === 'super_admin';
    }

    public function isAdminOrAbove(): bool
    {
        return $this->is_active && in_array($this->role, ['super_admin', 'administrator'], true);
    }

    public function isAnalystOrAbove(): bool
    {
        return $this->is_active && in_array($this->role, ['super_admin', 'administrator', 'security_analyst'], true);
    }

    public function canManageUsers(): bool
    {
        return $this->isSuperAdmin();
    }

    public function canManageSources(): bool
    {
        return $this->isAdminOrAbove();
    }

    public function canManageSettings(): bool
    {
        return $this->isAdminOrAbove();
    }

    public function canExportLogs(): bool
    {
        return $this->isAnalystOrAbove();
    }
}
