<?php

namespace Database\Seeders;

use App\Models\AlertRule;
use App\Models\AuthorizedSubnet;
use App\Models\LogSource;
use App\Models\SavedSearch;
use App\Models\SystemSetting;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        $superAdmin = User::updateOrCreate(
            ['email' => 'admin@syslog.local'],
            [
                'name' => 'SOC Super Admin',
                'password' => Hash::make('Admin@Syslog2026!'),
                'role' => 'super_admin',
                'is_active' => true,
                'timezone' => 'UTC',
            ]
        );

        User::updateOrCreate(
            ['email' => 'ops@syslog.local'],
            [
                'name' => 'Platform Administrator',
                'password' => Hash::make('Ops@Syslog2026!'),
                'role' => 'administrator',
                'is_active' => true,
                'timezone' => 'UTC',
            ]
        );

        $analyst = User::updateOrCreate(
            ['email' => 'analyst@syslog.local'],
            [
                'name' => 'Lead Security Analyst',
                'password' => Hash::make('Analyst@Syslog2026!'),
                'role' => 'security_analyst',
                'is_active' => true,
                'timezone' => 'UTC',
            ]
        );

        User::updateOrCreate(
            ['email' => 'viewer@syslog.local'],
            [
                'name' => 'NOC Read-Only Auditor',
                'password' => Hash::make('Viewer@Syslog2026!'),
                'role' => 'read_only',
                'is_active' => true,
                'timezone' => 'UTC',
            ]
        );

        // Default System Settings
        $settings = [
            ['hot_retention_days', '30', 'retention', 'Days to keep hot indexed logs in SQLite FTS5'],
            ['archive_retention_days', '90', 'retention', 'Days to keep compressed .gz raw log archives on disk'],
            ['disk_warning_percent', '75', 'storage', 'Disk usage percentage that triggers warning state'],
            ['disk_critical_percent', '85', 'storage', 'Disk usage percentage that triggers critical alert'],
            ['disk_emergency_prune_percent', '90', 'storage', 'Disk usage watermark for emergency unpinned log pruning'],
            ['default_timezone', 'UTC', 'general', 'Default portal display timezone'],
            ['restrict_unauthorized_sources', '1', 'security', 'Enforce rsyslog $AllowedSender network ACLs'],
            ['notification_email', 'soc-alerts@syslog.local', 'notifications', 'Default recipient for email alerts'],
            ['telegram_bot_token', '', 'notifications', 'Telegram Bot API Token (optional)'],
            ['telegram_chat_id', '', 'notifications', 'Telegram Chat ID for SOC channel (optional)'],
        ];
        foreach ($settings as [$k, $v, $g, $d]) {
            SystemSetting::setValue($k, $v, $g, $d);
        }

        // Default Authorized Subnets
        $subnets = [
            ['127.0.0.0/8', 'ANY', 'Local Loopback Network'],
            ['10.0.0.0/8', 'ANY', 'Private Corporate & Datacenter Subnets (RFC1918)'],
            ['172.16.0.0/12', 'ANY', 'Private Cloud & Container Subnets (RFC1918)'],
            ['192.168.0.0/16', 'ANY', 'Branch Office & Management LAN (RFC1918)'],
            ['103.72.109.0/27', 'ANY', 'Primary Datacenter Public Segment'],
        ];
        foreach ($subnets as [$cidr, $proto, $desc]) {
            AuthorizedSubnet::updateOrCreate(
                ['cidr' => $cidr],
                ['protocol' => $proto, 'description' => $desc, 'is_active' => true, 'created_by' => $superAdmin->id]
            );
        }

        // Default Log Sources
        LogSource::updateOrCreate(
            ['ip_address' => '127.0.0.1'],
            [
                'name' => 'Central Syslog Server (syslog)',
                'hostname' => 'syslog',
                'os_type' => 'Ubuntu 24.04 LTS',
                'environment' => 'Production',
                'location' => 'DC-1 Core',
                'owner' => 'SecOps Team',
                'description' => 'Primary centralized syslog receiver and local collector.',
                'is_enabled' => true,
                'heartbeat_threshold_minutes' => 15,
                'last_seen_at' => now(),
                'last_protocol' => 'LOCAL',
                'alert_on_silent' => true,
            ]
        );

        LogSource::updateOrCreate(
            ['ip_address' => '10.10.20.15'],
            [
                'name' => 'Production DB Primary (db-prod-01)',
                'hostname' => 'db-prod-01',
                'os_type' => 'Rocky Linux 9',
                'environment' => 'Production',
                'location' => 'DC-1 Database Zone',
                'owner' => 'DBA Team',
                'description' => 'PostgreSQL / MariaDB cluster node sending TLS 6514 logs.',
                'is_enabled' => true,
                'heartbeat_threshold_minutes' => 15,
                'last_seen_at' => now()->subMinutes(2),
                'last_protocol' => 'TLS',
                'alert_on_silent' => true,
            ]
        );

        LogSource::updateOrCreate(
            ['ip_address' => '10.10.1.1'],
            [
                'name' => 'Edge Perimeter Firewall (fw-edge-01)',
                'hostname' => 'fw-edge-01',
                'os_type' => 'Firewall Appliance',
                'environment' => 'DMZ',
                'location' => 'DC-1 Perimeter',
                'owner' => 'NetSec Team',
                'description' => 'Perimeter firewall forwarding packet filter and VPN logs over UDP/TCP 514.',
                'is_enabled' => true,
                'heartbeat_threshold_minutes' => 10,
                'last_seen_at' => now()->subMinutes(3),
                'last_protocol' => 'UDP',
                'alert_on_silent' => true,
            ]
        );

        LogSource::updateOrCreate(
            ['ip_address' => '10.10.50.99'],
            [
                'name' => 'Legacy Backup Node (backup-vault-02)',
                'hostname' => 'backup-vault-02',
                'os_type' => 'AlmaLinux 9',
                'environment' => 'Production',
                'location' => 'DR Vault',
                'owner' => 'Storage Ops',
                'description' => 'Cold backup server (currently delayed/offline demonstration source).',
                'is_enabled' => true,
                'heartbeat_threshold_minutes' => 15,
                'last_seen_at' => now()->subHours(3),
                'last_protocol' => 'TCP',
                'alert_on_silent' => true,
            ]
        );

        // Default Alert Rules
        $rules = [
            [
                'name' => 'SSH Brute-Force Indicator (>= 5 failures / 5m)',
                'rule_type' => 'ssh_bruteforce',
                'pattern' => 'Failed password',
                'severity_threshold' => 4,
                'threshold_count' => 5,
                'window_minutes' => 5,
                'cooldown_minutes' => 15,
                'channels' => ['email'],
                'recipients' => 'soc-alerts@syslog.local',
                'is_enabled' => true,
            ],
            [
                'name' => 'Repeated Authentication Failures (>= 5 / 5m)',
                'rule_type' => 'auth_failure',
                'pattern' => null,
                'severity_threshold' => 4,
                'threshold_count' => 5,
                'window_minutes' => 5,
                'cooldown_minutes' => 15,
                'channels' => ['email'],
                'recipients' => 'soc-alerts@syslog.local',
                'is_enabled' => true,
            ],
            [
                'name' => 'Critical & Emergency Syslog Messages',
                'rule_type' => 'critical_severity',
                'pattern' => null,
                'severity_threshold' => 2,
                'threshold_count' => 1,
                'window_minutes' => 5,
                'cooldown_minutes' => 10,
                'channels' => ['email', 'telegram'],
                'recipients' => 'soc-alerts@syslog.local',
                'is_enabled' => true,
            ],
            [
                'name' => 'Unexpected Service Shutdown or Crash',
                'rule_type' => 'service_failure',
                'pattern' => null,
                'severity_threshold' => 3,
                'threshold_count' => 2,
                'window_minutes' => 10,
                'cooldown_minutes' => 15,
                'channels' => ['email'],
                'recipients' => 'ops@syslog.local',
                'is_enabled' => true,
            ],
            [
                'name' => 'Disk Usage Threshold Exceeded (>= 75%)',
                'rule_type' => 'disk_usage',
                'pattern' => null,
                'severity_threshold' => null,
                'threshold_count' => 75,
                'window_minutes' => 15,
                'cooldown_minutes' => 60,
                'channels' => ['email'],
                'recipients' => 'ops@syslog.local',
                'is_enabled' => true,
            ],
            [
                'name' => 'Sudden Log Volume Spike (>= 5000 events / 5m)',
                'rule_type' => 'volume_spike',
                'pattern' => null,
                'severity_threshold' => null,
                'threshold_count' => 5000,
                'window_minutes' => 5,
                'cooldown_minutes' => 30,
                'channels' => ['email'],
                'recipients' => 'soc-alerts@syslog.local',
                'is_enabled' => true,
            ],
            [
                'name' => 'Registered Server Silent / Offline',
                'rule_type' => 'silent_source',
                'pattern' => null,
                'severity_threshold' => null,
                'threshold_count' => 1,
                'window_minutes' => 15,
                'cooldown_minutes' => 60,
                'channels' => ['email'],
                'recipients' => 'ops@syslog.local',
                'is_enabled' => true,
            ],
            [
                'name' => 'Kernel Out-of-Memory (OOM) / Segfault Detector',
                'rule_type' => 'custom_pattern',
                'pattern' => 'Out of memory',
                'severity_threshold' => 3,
                'threshold_count' => 1,
                'window_minutes' => 10,
                'cooldown_minutes' => 15,
                'channels' => ['email'],
                'recipients' => 'ops@syslog.local',
                'is_enabled' => true,
            ],
        ];
        foreach ($rules as $r) {
            AlertRule::updateOrCreate(['name' => $r['name']], $r);
        }

        // Default Saved Searches
        SavedSearch::updateOrCreate(
            ['user_id' => $analyst->id, 'name' => 'SSH Failed Logins (All Hosts)'],
            ['is_shared' => true, 'filters' => ['quick_filter' => 'auth_failure', 'q' => 'Failed password']]
        );
        SavedSearch::updateOrCreate(
            ['user_id' => $analyst->id, 'name' => 'Perimeter Firewall Blocks'],
            ['is_shared' => true, 'filters' => ['quick_filter' => 'firewall']]
        );
        SavedSearch::updateOrCreate(
            ['user_id' => $analyst->id, 'name' => 'Critical & Emergency Alerts (24h)'],
            ['is_shared' => true, 'filters' => ['quick_filter' => 'critical_only']]
        );
    }
}
