<?php

namespace App\Providers;

use App\Models\User;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        //
    }

    public function boot(): void
    {
        if (request()->header('X-Forwarded-Proto') === 'https' || request()->isSecure()) {
            URL::forceScheme('https');
        }

        // RBAC Authorization Gates enforced server-side
        Gate::define('manage-users', fn(User $user) => $user->canManageUsers());
        Gate::define('manage-sources', fn(User $user) => $user->canManageSources());
        Gate::define('manage-settings', fn(User $user) => $user->canManageSettings());
        Gate::define('export-logs', fn(User $user) => $user->canExportLogs());
        Gate::define('investigate-logs', fn(User $user) => $user->isAnalystOrAbove());

        // Brute-force and DoS Rate Limiters
        RateLimiter::for('login', function (Request $request) {
            $key = strtolower((string) $request->input('email')) . '|' . $request->ip();
            return Limit::perMinute(5)->by($key);
        });

        RateLimiter::for('log-search', function (Request $request) {
            return Limit::perMinute(60)->by($request->user()?->id ?: $request->ip());
        });

        RateLimiter::for('log-export', function (Request $request) {
            return Limit::perMinute(10)->by($request->user()?->id ?: $request->ip());
        });
    }
}
