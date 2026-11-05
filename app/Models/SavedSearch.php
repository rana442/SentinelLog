<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class SavedSearch extends Model
{
    protected $fillable = [
        'user_id',
        'name',
        'is_shared',
        'filters',
    ];

    protected function casts(): array
    {
        return [
            'is_shared' => 'boolean',
            'filters' => 'array',
        ];
    }
}
