<?php

namespace App\Services;

use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\Request;

class AuditService
{
    public static function record(
        string $action,
        ?string $targetType = null,
        ?string $targetId = null,
        array $metadata = [],
        ?User $actor = null,
        ?Request $request = null
    ): AuditLog {
        $request = $request ?? request();
        $actor = $actor ?? ($request ? $request->user() : null);

        $actorName = $actor ? $actor->name : ($metadata['actor_name'] ?? 'System / Anonymous');
        $actorEmail = $actor ? $actor->email : ($metadata['actor_email'] ?? null);
        $actorRole = $actor ? $actor->role : ($metadata['actor_role'] ?? 'unauthenticated');
        $ip = $request ? $request->ip() : '127.0.0.1';
        $ua = $request ? substr((string) $request->userAgent(), 0, 500) : 'CLI';
        $timestamp = now()->toIso8601String();

        $lastHash = AuditLog::orderByDesc('id')->value('integrity_hash') ?? str_repeat('0', 64);
        $payload = implode('|', [
            $lastHash,
            (string) ($actor?->id ?? 0),
            $actorEmail ?? '',
            $action,
            $targetType ?? '',
            $targetId ?? '',
            $ip,
            json_encode($metadata),
            $timestamp,
        ]);
        $integrityHash = hash('sha256', $payload);

        $audit = AuditLog::create([
            'user_id' => $actor?->id,
            'actor_name' => $actorName,
            'actor_email' => $actorEmail,
            'actor_role' => $actorRole,
            'action' => $action,
            'target_type' => $targetType,
            'target_id' => $targetId,
            'ip_address' => $ip,
            'user_agent' => $ua,
            'metadata' => $metadata,
            'integrity_hash' => $integrityHash,
            'created_at' => now(),
        ]);

        // Mirror to structured JSON file for Wazuh SIEM ingestion
        $wazuhPayload = json_encode([
            'timestamp' => $timestamp,
            'integration' => 'sentinellog_portal_audit',
            'audit_id' => $audit->id,
            'actor_name' => $actorName,
            'actor_email' => $actorEmail,
            'actor_role' => $actorRole,
            'action' => $action,
            'target_type' => $targetType,
            'target_id' => $targetId,
            'srcip' => $ip,
            'user_agent' => $ua,
            'metadata' => $metadata,
            'integrity_hash' => $integrityHash,
        ], JSON_UNESCAPED_SLASHES);

        @file_put_contents('/var/log/central-syslog/portal-audit.json', $wazuhPayload . "\n", FILE_APPEND | LOCK_EX);

        return $audit;
    }
}
