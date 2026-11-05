<?php

use App\Http\Controllers\AlertController;
use App\Http\Controllers\AuditController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\LiveLogController;
use App\Http\Controllers\LogExplorerController;
use App\Http\Controllers\SettingController;
use App\Http\Controllers\SourceController;
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

// Guest Authentication Routes
Route::middleware('guest')->group(function () {
    Route::get('/login', [AuthController::class, 'showLogin'])->name('login');
    Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:login')->name('login.submit');
    Route::get('/forgot-password', [AuthController::class, 'showForgotPassword'])->name('password.request');
    Route::post('/forgot-password', [AuthController::class, 'sendResetLink'])->middleware('throttle:login')->name('password.email');
});

// All Portal, Log, API, Export, and Administrative Routes Require Authentication
Route::middleware('auth')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
    Route::post('/profile/password', [AuthController::class, 'updatePassword'])->name('profile.password');

    // Dashboard & Live Metrics
    Route::get('/', [DashboardController::class, 'index'])->name('dashboard');
    Route::get('/api/dashboard/metrics', [DashboardController::class, 'liveMetrics'])->name('dashboard.metrics');

    // Live Logs Stream
    Route::get('/logs/live', [LiveLogController::class, 'index'])->name('logs.live');
    Route::get('/api/logs/poll', [LiveLogController::class, 'poll'])->middleware('throttle:log-search')->name('logs.poll');

    // Log Explorer, Details, Saved Searches & Audited CSV Export
    Route::get('/logs/explorer', [LogExplorerController::class, 'index'])->middleware('throttle:log-search')->name('logs.explorer');
    Route::get('/api/logs/{id}', [LogExplorerController::class, 'show'])->whereNumber('id')->name('logs.show');
    Route::post('/logs/{id}/pin', [LogExplorerController::class, 'togglePin'])->whereNumber('id')->name('logs.pin');
    Route::post('/logs/saved-searches', [LogExplorerController::class, 'saveSearch'])->name('logs.searches.store');
    Route::delete('/logs/saved-searches/{search}', [LogExplorerController::class, 'deleteSearch'])->name('logs.searches.destroy');
    Route::get('/logs/export/csv', [LogExplorerController::class, 'exportCsv'])->middleware('throttle:log-export')->name('logs.export.csv');

    // Log Sources & Authorized Subnets
    Route::get('/sources', [SourceController::class, 'index'])->name('sources.index');
    Route::post('/sources', [SourceController::class, 'store'])->name('sources.store');
    Route::put('/sources/{source}', [SourceController::class, 'update'])->name('sources.update');
    Route::post('/sources/{source}/toggle', [SourceController::class, 'toggle'])->name('sources.toggle');
    Route::delete('/sources/{source}', [SourceController::class, 'destroy'])->name('sources.destroy');
    Route::post('/sources/subnets', [SourceController::class, 'storeSubnet'])->name('sources.subnets.store');
    Route::delete('/sources/subnets/{subnet}', [SourceController::class, 'destroySubnet'])->name('sources.subnets.destroy');

    // Alerts & Notification Rules
    Route::get('/alerts', [AlertController::class, 'index'])->name('alerts.index');
    Route::post('/alerts/rules', [AlertController::class, 'storeRule'])->name('alerts.rules.store');
    Route::post('/alerts/rules/{rule}/toggle', [AlertController::class, 'toggleRule'])->name('alerts.rules.toggle');
    Route::delete('/alerts/rules/{rule}', [AlertController::class, 'destroyRule'])->name('alerts.rules.destroy');
    Route::post('/alerts/incidents/{incident}/status', [AlertController::class, 'updateIncidentStatus'])->name('alerts.incidents.status');
    Route::post('/alerts/evaluate', [AlertController::class, 'evaluateNow'])->name('alerts.evaluate');

    // Users & RBAC (Super Admin enforced via Gate in controller)
    Route::get('/users', [UserController::class, 'index'])->name('users.index');
    Route::post('/users', [UserController::class, 'store'])->name('users.store');
    Route::put('/users/{user}/role', [UserController::class, 'updateRole'])->name('users.role');
    Route::post('/users/{user}/toggle', [UserController::class, 'toggleActive'])->name('users.toggle');

    // Immutable Application Audit Trail
    Route::get('/audit', [AuditController::class, 'index'])->name('audit.index');

    // Retention, Storage & System Settings
    Route::get('/settings', [SettingController::class, 'index'])->name('settings.index');
    Route::put('/settings', [SettingController::class, 'update'])->name('settings.update');
    Route::post('/settings/maintenance', [SettingController::class, 'runMaintenance'])->name('settings.maintenance');
});
