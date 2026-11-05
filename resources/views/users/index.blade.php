@extends('layouts.app')
@section('title', 'Users & Role-Based Access Control')
@section('heading', 'User Management & RBAC Administration')
@section('subheading', 'Super Admin control panel for operator accounts, role assignments, and session access')

@section('content')
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <div class="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-800">
            <h2 class="text-sm font-bold text-white">Portal Operators</h2>
        </div>
        <div class="overflow-x-auto">
            <table class="w-full text-left text-xs">
                <thead class="bg-slate-950 text-slate-400 uppercase text-[11px]">
                    <tr>
                        <th class="px-4 py-3">Name / Email</th>
                        <th class="px-4 py-3">Role &amp; Timezone</th>
                        <th class="px-4 py-3">Status</th>
                        <th class="px-4 py-3">Last Login</th>
                        <th class="px-4 py-3 text-right">Actions</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-800/80">
                    @foreach($users as $u)
                        <tr>
                            <td class="px-4 py-3">
                                <div class="font-semibold text-white">{{ $u->name }}</div>
                                <div class="font-mono text-slate-400">{{ $u->email }}</div>
                            </td>
                            <td class="px-4 py-3">
                                <form method="POST" action="{{ route('users.role', $u) }}" class="flex items-center gap-1.5">
                                    @csrf
                                    @method('PUT')
                                    <select name="role" class="rounded bg-slate-950 border border-slate-700 px-2 py-1 text-white text-[11px]">
                                        @foreach(config('syslog.roles') as $rk => $rl)
                                            <option value="{{ $rk }}" @selected($u->role === $rk)>{{ $rl }}</option>
                                        @endforeach
                                    </select>
                                    <input type="hidden" name="timezone" value="{{ $u->timezone }}">
                                    <button type="submit" class="px-2 py-1 rounded bg-cyan-500/20 text-cyan-300 text-[11px]">Save</button>
                                </form>
                            </td>
                            <td class="px-4 py-3">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold {{ $u->is_active ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300' }}">
                                    {{ $u->is_active ? 'ACTIVE' : 'DISABLED' }}
                                </span>
                            </td>
                            <td class="px-4 py-3 font-mono text-[11px] text-slate-400">
                                {{ $u->last_login_at ? $u->last_login_at->format('Y-m-d H:i') . ' (' . $u->last_login_ip . ')' : 'Never' }}
                            </td>
                            <td class="px-4 py-3 text-right">
                                @if($u->id !== auth()->id())
                                    <form method="POST" action="{{ route('users.toggle', $u) }}">
                                        @csrf
                                        <button type="submit" class="px-2.5 py-1 rounded {{ $u->is_active ? 'bg-rose-500/15 text-rose-300' : 'bg-emerald-500/15 text-emerald-300' }} text-[11px]">
                                            {{ $u->is_active ? 'Deactivate' : 'Activate' }}
                                        </button>
                                    </form>
                                @endif
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    </div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 class="text-sm font-bold text-white">Create Operator Account</h3>
        <form method="POST" action="{{ route('users.store') }}" class="space-y-3 text-xs">
            @csrf
            <div>
                <label class="block text-slate-400 mb-1">Full Name</label>
                <input type="text" name="name" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
            </div>
            <div>
                <label class="block text-slate-400 mb-1">Email Address</label>
                <input type="email" name="email" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
            </div>
            <div>
                <label class="block text-slate-400 mb-1">Assigned RBAC Role</label>
                <select name="role" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
                    @foreach(config('syslog.roles') as $rk => $rl)
                        <option value="{{ $rk }}">{{ $rl }}</option>
                    @endforeach
                </select>
            </div>
            <div>
                <label class="block text-slate-400 mb-1">Display Timezone</label>
                <select name="timezone" class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white font-mono">
                    <option value="UTC">UTC</option>
                    <option value="Asia/Dhaka">Asia/Dhaka (+06:00)</option>
                    <option value="Europe/London">Europe/London</option>
                    <option value="America/New_York">America/New_York</option>
                </select>
            </div>
            <div>
                <label class="block text-slate-400 mb-1">Strong Password (min 10 chars, mixed case, number, symbol)</label>
                <input type="password" name="password" required class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-white">
            </div>
            <button type="submit" class="w-full py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold">
                Provision Operator
            </button>
        </form>
    </div>
</div>
@endsection
