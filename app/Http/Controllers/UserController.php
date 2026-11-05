<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Services\AuditService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules\Password as PasswordRule;

class UserController extends Controller
{
    public function index()
    {
        Gate::authorize('manage-users');
        $users = User::orderBy('id')->get();
        return view('users.index', ['users' => $users]);
    }

    public function store(Request $request)
    {
        Gate::authorize('manage-users');

        $validated = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'email' => ['required', 'email', 'max:191', 'unique:users,email'],
            'role' => ['required', 'in:super_admin,administrator,security_analyst,read_only'],
            'timezone' => ['required', 'string', 'max:64'],
            'password' => ['required', PasswordRule::min(10)->mixedCase()->numbers()->symbols()],
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'role' => $validated['role'],
            'timezone' => $validated['timezone'],
            'password' => Hash::make($validated['password']),
            'is_active' => true,
        ]);

        AuditService::record('user.created', 'user', (string) $user->id, [
            'email' => $user->email,
            'role' => $user->role,
        ]);

        return back()->with('status', "User '{$user->name}' ({$user->roleLabel()}) created.");
    }

    public function updateRole(Request $request, User $user)
    {
        Gate::authorize('manage-users');

        $validated = $request->validate([
            'role' => ['required', 'in:super_admin,administrator,security_analyst,read_only'],
            'timezone' => ['required', 'string', 'max:64'],
        ]);

        if ($user->id === $request->user()->id && $validated['role'] !== 'super_admin') {
            return back()->withErrors(['role' => 'You cannot downgrade your own Super Admin role.']);
        }

        $oldRole = $user->role;
        $user->update($validated);

        AuditService::record('user.role_updated', 'user', (string) $user->id, [
            'email' => $user->email,
            'old_role' => $oldRole,
            'new_role' => $user->role,
        ]);

        return back()->with('status', "Updated role for {$user->email} to {$user->roleLabel()}.");
    }

    public function toggleActive(Request $request, User $user)
    {
        Gate::authorize('manage-users');

        if ($user->id === $request->user()->id) {
            return back()->withErrors(['user' => 'You cannot deactivate your own account.']);
        }

        $user->update(['is_active' => !$user->is_active]);

        AuditService::record($user->is_active ? 'user.activated' : 'user.deactivated', 'user', (string) $user->id, [
            'email' => $user->email,
        ]);

        return back()->with('status', "Account {$user->email} " . ($user->is_active ? 'activated' : 'deactivated') . '.');
    }
}
