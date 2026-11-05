<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Password Reset ? SentinelLog Central Syslog Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-8 space-y-6">
        <div>
            <h1 class="text-lg font-bold text-white">Reset Operator Password</h1>
            <p class="text-xs text-slate-400 mt-1">Enter your registered operator email to request a password reset link.</p>
        </div>

        @if (session('status'))
            <div class="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300">
                {{ session('status') }}
            </div>
        @endif

        <form method="POST" action="{{ route('password.email') }}" class="space-y-4">
            @csrf
            <div>
                <label class="block text-xs font-medium text-slate-300 mb-1">Operator Email</label>
                <input type="email" name="email" required autofocus
                    class="w-full rounded-lg bg-slate-950 border border-slate-700 px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-500">
            </div>
            <button type="submit" class="w-full py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm transition">
                Send Password Reset Instructions
            </button>
        </form>

        <div class="text-center">
            <a href="{{ route('login') }}" class="text-xs text-cyan-400 hover:underline">&larr; Return to login</a>
        </div>
    </div>
</body>
</html>
