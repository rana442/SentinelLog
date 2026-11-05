<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('role', 32)->default('read_only')->after('email');
            $table->boolean('is_active')->default(true)->after('role');
            $table->string('timezone', 64)->default('UTC')->after('is_active');
            $table->timestamp('last_login_at')->nullable()->after('timezone');
            $table->string('last_login_ip', 45)->nullable()->after('last_login_at');
            $table->index(['role', 'is_active']);
        });

        Schema::create('log_sources', function (Blueprint $table) {
            $table->id();
            $table->string('name', 120);
            $table->string('hostname', 191)->index();
            $table->string('ip_address', 45)->unique();
            $table->string('os_type', 64)->default('Ubuntu');
            $table->string('environment', 64)->default('Production');
            $table->string('location', 120)->nullable();
            $table->string('owner', 120)->nullable();
            $table->text('description')->nullable();
            $table->boolean('is_enabled')->default(true);
            $table->unsignedInteger('heartbeat_threshold_minutes')->default(15);
            $table->timestamp('last_seen_at')->nullable()->index();
            $table->string('last_protocol', 16)->nullable();
            $table->unsignedBigInteger('events_5m')->default(0);
            $table->unsignedBigInteger('events_24h')->default(0);
            $table->unsignedBigInteger('total_events')->default(0);
            $table->boolean('alert_on_silent')->default(true);
            $table->timestamp('silent_alerted_at')->nullable();
            $table->timestamps();
        });

        Schema::create('authorized_subnets', function (Blueprint $table) {
            $table->id();
            $table->string('cidr', 64)->unique();
            $table->string('protocol', 16)->default('ANY');
            $table->string('description', 255)->nullable();
            $table->boolean('is_active')->default(true);
            $table->foreignId('created_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();
        });

        Schema::create('saved_searches', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->string('name', 120);
            $table->boolean('is_shared')->default(false);
            $table->json('filters');
            $table->timestamps();
        });

        Schema::create('alert_rules', function (Blueprint $table) {
            $table->id();
            $table->string('name', 150);
            $table->string('rule_type', 64)->index(); // auth_failure, ssh_bruteforce, critical_severity, service_failure, disk_usage, volume_spike, silent_source, custom_pattern
            $table->string('pattern', 255)->nullable();
            $table->unsignedTinyInteger('severity_threshold')->nullable();
            $table->unsignedInteger('threshold_count')->default(5);
            $table->unsignedInteger('window_minutes')->default(5);
            $table->unsignedInteger('cooldown_minutes')->default(15);
            $table->json('channels');
            $table->string('recipients', 255)->nullable();
            $table->boolean('is_enabled')->default(true);
            $table->timestamp('last_triggered_at')->nullable();
            $table->timestamps();
        });

        Schema::create('alert_incidents', function (Blueprint $table) {
            $table->id();
            $table->foreignId('alert_rule_id')->nullable()->constrained('alert_rules')->nullOnDelete();
            $table->string('dedup_key', 191)->index();
            $table->string('severity', 32)->default('warning')->index();
            $table->string('title', 255);
            $table->text('summary');
            $table->string('source_host', 191)->nullable()->index();
            $table->string('source_ip', 45)->nullable();
            $table->unsignedInteger('match_count')->default(1);
            $table->json('sample_payload')->nullable();
            $table->string('status', 32)->default('open')->index(); // open, acknowledged, resolved
            $table->json('notified_channels')->nullable();
            $table->foreignId('acknowledged_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('acknowledged_at')->nullable();
            $table->timestamp('triggered_at')->index();
            $table->timestamps();
        });

        Schema::create('audit_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('actor_name', 120);
            $table->string('actor_email', 191)->nullable();
            $table->string('actor_role', 64)->nullable();
            $table->string('action', 100)->index();
            $table->string('target_type', 100)->nullable();
            $table->string('target_id', 100)->nullable();
            $table->string('ip_address', 45)->nullable()->index();
            $table->string('user_agent', 512)->nullable();
            $table->json('metadata')->nullable();
            $table->string('integrity_hash', 64)->index();
            $table->timestamp('created_at')->index();
        });

        Schema::create('system_settings', function (Blueprint $table) {
            $table->id();
            $table->string('key', 100)->unique();
            $table->text('value')->nullable();
            $table->string('group', 64)->default('general');
            $table->string('description', 255)->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('system_settings');
        Schema::dropIfExists('audit_logs');
        Schema::dropIfExists('alert_incidents');
        Schema::dropIfExists('alert_rules');
        Schema::dropIfExists('saved_searches');
        Schema::dropIfExists('authorized_subnets');
        Schema::dropIfExists('log_sources');
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn(['role', 'is_active', 'timezone', 'last_login_at', 'last_login_ip']);
        });
    }
};
