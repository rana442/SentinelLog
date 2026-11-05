<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login ? SentinelLog Central Syslog Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-8 space-y-6">
        <div class="flex items-center space-x-3">
            <div class="h-11 w-11 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-mono font-bold text-lg">
                SL
            </div>
            <div>
                <h1 class="text-lg font-bold text-white">SentinelLog SOC Portal</h1>
                <p class="text-xs text-slate-400">Authenticated Centralized Syslog Platform</p>
            </div>
        </div>

        @if (session('status'))
            <div class="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300">
                {{ session('status') }}
            </div>
        @endif

        @if ($errors->any())
            <div class="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
                {{ $errors->first() }}
            </div>
        @endif

        <form method="POST" action="{{ route('login.submit') }}" class="space-y-4">
            @csrf
            <div>
                <label class="block text-xs font-medium text-slate-300 mb-1">Operator Email</label>
                <input type="email" name="email" value="{{ old('email') }}" required autofocus
                    class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-500"
                    placeholder="admin@syslog.local">
            </div>

            <div>
                <div class="flex items-center justify-between mb-1">
                    <label class="block text-xs font-medium text-slate-300">Password</label>
                    <a href="{{ route('password.request') }}" class="text-xs text-cyan-400 hover:underline">Forgot password?</a>
                </div>
                <input type="password" name="password" required
                    class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-500">
            </div>

            <div class="flex items-center justify-between text-xs text-slate-400">
                <label class="flex items-center space-x-2">
                    <input type="checkbox" name="remember" class="rounded bg-slate-950 border-slate-700 text-cyan-500">
                    <span>Remember session</span>
                </label>
                <span class="font-mono text-[11px]">Rate-limited: 5/min</span>
            </div>

            <button type="submit" class="w-full py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm transition">
                Sign In to SOC Console
            </button>
        </form>

        <div class="pt-4 border-t border-slate-800 text-[11px] text-slate-500 space-y-1">
            <div>All authentication attempts and search queries are recorded in the SHA-256 chained audit trail.</div>
        </div>
    </div>
</body>
</html>
