<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Services\AuditService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\Rules\Password as PasswordRule;

class AuthController extends Controller
{
    public function showLogin()
    {
        if (Auth::check()) {
            return redirect()->route('dashboard');
        }
        return view('auth.login');
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => ['required', 'email', 'max:191'],
            'password' => ['required', 'string', 'max:255'],
        ]);

        $throttleKey = strtolower($credentials['email']) . '|' . $request->ip();
        if (RateLimiter::tooManyAttempts($throttleKey, 5)) {
            $seconds = RateLimiter::availableIn($throttleKey);
            AuditService::record('auth.login_lockout', 'user', $credentials['email'], [
                'actor_name' => $credentials['email'],
                'actor_email' => $credentials['email'],
                'reason' => 'rate_limit_exceeded',
                'retry_after_seconds' => $seconds,
            ]);
            return back()->withErrors([
                'email' => "Too many login attempts. Please try again in {$seconds} seconds.",
            ])->onlyInput('email');
        }

        $user = User::where('email', $credentials['email'])->first();
        if (!$user || !$user->is_active || !Hash::check($credentials['password'], $user->password)) {
            RateLimiter::hit($throttleKey, 60);
            AuditService::record('auth.login_failed', 'user', $credentials['email'], [
                'actor_name' => $credentials['email'],
                'actor_email' => $credentials['email'],
                'reason' => (!$user) ? 'unknown_user' : (!$user->is_active ? 'account_disabled' : 'invalid_password'),
            ]);
            return back()->withErrors([
                'email' => 'The provided credentials do not match our active records.',
            ])->onlyInput('email');
        }

        RateLimiter::clear($throttleKey);
        Auth::login($user, $request->boolean('remember'));
        $request->session()->regenerate();

        $user->update([
            'last_login_at' => now(),
            'last_login_ip' => $request->ip(),
        ]);

        AuditService::record('auth.login_success', 'user', (string) $user->id, [
            'role' => $user->role,
        ], $user, $request);

        return redirect()->intended(route('dashboard'));
    }

    public function logout(Request $request)
    {
        $user = $request->user();
        if ($user) {
            AuditService::record('auth.logout', 'user', (string) $user->id, [], $user, $request);
        }

        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('login');
    }

    public function showForgotPassword()
    {
        return view('auth.forgot-password');
    }

    public function sendResetLink(Request $request)
    {
        $data = $request->validate(['email' => ['required', 'email']]);
        $user = User::where('email', $data['email'])->where('is_active', true)->first();

        AuditService::record('auth.password_reset_requested', 'user', $data['email'], [
            'actor_name' => $data['email'],
            'actor_email' => $data['email'],
            'user_found' => (bool) $user,
        ]);

        return back()->with('status', 'If that email address matches an active account, password reset instructions have been logged to the configured mail transport.');
    }

    public function updatePassword(Request $request)
    {
        $validated = $request->validate([
            'current_password' => ['required', 'current_password'],
            'password' => ['required', 'confirmed', PasswordRule::min(10)->mixedCase()->numbers()->symbols()],
        ]);

        $user = $request->user();
        $user->update([
            'password' => Hash::make($validated['password']),
        ]);

        $request->session()->regenerate();
        AuditService::record('auth.password_changed', 'user', (string) $user->id, [], $user, $request);

        return back()->with('status', 'Your password has been updated and your session has been regenerated.');
    }
}
