<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;

class SystemSetting extends Model
{
    protected $fillable = [
        'key',
        'value',
        'group',
        'description',
    ];

    public static function getValue(string $key, mixed $default = null): mixed
    {
        return Cache::remember("sys_setting:{$key}", 60, function () use ($key, $default) {
            $row = static::where('key', $key)->first();
            return $row ? $row->value : $default;
        });
    }

    public static function setValue(string $key, mixed $value, string $group = 'general', ?string $description = null): self
    {
        $setting = static::updateOrCreate(
            ['key' => $key],
            array_filter([
                'value' => (string) $value,
                'group' => $group,
                'description' => $description,
            ], fn($v) => $v !== null)
        );
        Cache::forget("sys_setting:{$key}");
        return $setting;
    }
}
