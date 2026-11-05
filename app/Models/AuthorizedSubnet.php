<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class AuthorizedSubnet extends Model
{
    protected $fillable = [
        'cidr',
        'protocol',
        'description',
        'is_active',
        'created_by',
    ];

    protected function casts(): array
    {
        return [
            'is_active' => 'boolean',
        ];
    }
}
