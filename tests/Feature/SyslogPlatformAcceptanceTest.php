<?php

namespace Tests\Feature;

use App\Models\AuditLog;
use App\Models\LogSource;
use App\Models\User;
use App\Services\SyslogIndexService;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Hash;
use LogicException;
use Tests\TestCase;

class SyslogPlatformAcceptanceTest extends TestCase
{
    use DatabaseTransactions;

    protected SyslogIndexService $index;

    protected function setUp(): void
    {
        parent::setUp();
        $tmpSqlite = sys_get_temp_dir() . '/test_syslog_' . uniqid() . '.sqlite';
        config(['syslog.index_db' => $tmpSqlite]);
        $this->index = new SyslogIndexService($tmpSqlite);
        $this->app->instance(SyslogIndexService::class, $this->index);
    }

    public function test_anonymous_users_cannot_access_portal_or_apis(): void
    {
        $protectedRoutes = [
            '/',
            '/logs/live',
            '/logs/explorer',
            '/logs/export/csv',
            '/api/dashboard/metrics',
            '/api/logs/poll',
            '/api/logs/1',
            '/sources',
            '/alerts',
            '/users',
            '/audit',
            '/settings',
        ];

        foreach ($protectedRoutes as $uri) {
            $response = $this->get($uri);
            $response->assertRedirect('/login');
        }
    }

    public function test_login_records_audit_trail_for_success_and_failure(): void
    {
        $user = User::create([
            'name' => 'Test Analyst',
            'email' => 'test-analyst@syslog.local',
            'password' => Hash::make('ValidPass@2026!'),
            'role' => 'security_analyst',
            'is_active' => true,
            'timezone' => 'UTC',
        ]);

        // Failed login
        $failResp = $this->post('/login', [
            'email' => 'test-analyst@syslog.local',
            'password' => 'WrongPassword!',
        ]);
        $failResp->assertSessionHasErrors('email');
        $this->assertDatabaseHas('audit_logs', [
            'action' => 'auth.login_failed',
            'target_id' => 'test-analyst@syslog.local',
        ]);

        // Successful login
        $okResp = $this->post('/login', [
            'email' => 'test-analyst@syslog.local',
            'password' => 'ValidPass@2026!',
        ]);
        $okResp->assertRedirect(route('dashboard'));
        $this->assertDatabaseHas('audit_logs', [
            'action' => 'auth.login_success',
            'user_id' => $user->id,
        ]);
    }

    public function test_rbac_permissions_enforced_server_side_for_all_roles(): void
    {
        $readOnly = User::create([
            'name' => 'Read Only User',
            'email' => 'ro-test@syslog.local',
            'password' => Hash::make('Password@2026!'),
            'role' => 'read_only',
            'is_active' => true,
        ]);

        $analyst = User::create([
            'name' => 'Analyst User',
            'email' => 'an-test@syslog.local',
            'password' => Hash::make('Password@2026!'),
            'role' => 'security_analyst',
            'is_active' => true,
        ]);

        $admin = User::create([
            'name' => 'Admin User',
            'email' => 'ad-test@syslog.local',
            'password' => Hash::make('Password@2026!'),
            'role' => 'administrator',
            'is_active' => true,
        ]);

        $superAdmin = User::create([
            'name' => 'Super Admin User',
            'email' => 'sa-test@syslog.local',
            'password' => Hash::make('Password@2026!'),
            'role' => 'super_admin',
            'is_active' => true,
        ]);

        // Read Only can view dashboard & explorer, but 403 on export, source creation, settings, and users
        $this->actingAs($readOnly)->get('/')->assertStatus(200);
        $this->actingAs($readOnly)->get('/logs/explorer')->assertStatus(200);
        $this->actingAs($readOnly)->get('/logs/export/csv')->assertStatus(403);
        $this->actingAs($readOnly)->get('/settings')->assertStatus(403);
        $this->actingAs($readOnly)->get('/users')->assertStatus(403);

        // Security Analyst can export CSV, but 403 on settings and users
        $this->actingAs($analyst)->get('/logs/export/csv')->assertStatus(200);
        $this->actingAs($analyst)->get('/settings')->assertStatus(403);
        $this->actingAs($analyst)->get('/users')->assertStatus(403);

        // Administrator can access settings, but 403 on Super Admin user management
        $this->actingAs($admin)->get('/settings')->assertStatus(200);
        $this->actingAs($admin)->get('/users')->assertStatus(403);

        // Super Admin can access user management
        $this->actingAs($superAdmin)->get('/users')->assertStatus(200);
    }

    public function test_search_filtering_and_xss_control_char_sanitization(): void
    {
        $analyst = User::where('role', 'security_analyst')->first() ?? User::create([
            'name' => 'Analyst',
            'email' => 'analyst2@syslog.local',
            'password' => Hash::make('Password@2026!'),
            'role' => 'security_analyst',
            'is_active' => true,
        ]);

        $this->index->insertBatch([
            [
                'received_at' => now()->utc()->toIso8601String(),
                'reported_at' => now()->utc()->toIso8601String(),
                'source_ip' => '10.10.20.15',
                'hostname' => 'db-prod-01',
                'facility' => 'authpriv',
                'facility_num' => 10,
                'severity' => 'err',
                'severity_num' => 3,
                'app_name' => 'sshd',
                'proc_id' => '9912',
                'protocol' => 'TLS',
                'message' => "Failed password for root \x1b[31m<script>alert('xss')</script>\x1b[0m from 198.51.100.99",
                'raw_message' => "<83>Failed password for root <script>alert('xss')</script>",
            ],
        ]);

        $resp = $this->actingAs($analyst)->get('/logs/explorer?q=Failed+password&protocol=TLS&hostname=db-prod-01');
        $resp->assertStatus(200);
        // Ensure raw unescaped <script> tag is NOT present in HTML output, while escaped entity is present
        $resp->assertDontSee("<script>alert('xss')</script>", false);
        $resp->assertSee("&lt;script&gt;alert(&#039;xss&#039;)&lt;/script&gt;", false);
    }

    public function test_source_health_status_and_retention_pin_protection(): void
    {
        $unknownSource = new LogSource(['hostname' => 'never-seen', 'ip_address' => '10.99.99.1', 'heartbeat_threshold_minutes' => 15, 'last_seen_at' => null]);
        $this->assertSame('Unknown', $unknownSource->healthStatus());

        $onlineSource = new LogSource(['hostname' => 'online-srv', 'ip_address' => '10.99.99.2', 'heartbeat_threshold_minutes' => 15, 'last_seen_at' => now()->subMinutes(5)]);
        $this->assertSame('Online', $onlineSource->healthStatus());

        $offlineSource = new LogSource(['hostname' => 'offline-srv', 'ip_address' => '10.99.99.3', 'heartbeat_threshold_minutes' => 15, 'last_seen_at' => now()->subMinutes(45)]);
        $this->assertSame('Offline', $offlineSource->healthStatus());

        // Insert 2 old events (60 days old): pin one for active investigation, leave the other unpinned
        $inserted = $this->index->insertBatch([
            [
                'received_at' => now()->subDays(60)->toIso8601String(),
                'source_ip' => '10.10.20.15',
                'hostname' => 'db-prod-01',
                'facility' => 'auth',
                'severity_num' => 3,
                'app_name' => 'sshd',
                'protocol' => 'TCP',
                'message' => 'Old event to be pruned',
            ],
            [
                'received_at' => now()->subDays(60)->toIso8601String(),
                'source_ip' => '10.10.20.15',
                'hostname' => 'db-prod-01',
                'facility' => 'auth',
                'severity_num' => 1,
                'app_name' => 'sshd',
                'protocol' => 'TLS',
                'message' => 'Pinned active forensic investigation event',
            ],
        ]);

        $this->index->togglePin($inserted[1]['id']);
        $prunedCount = $this->index->pruneExpired(30, false);

        $this->assertSame(1, $prunedCount);
        $this->assertNull($this->index->findEvent($inserted[0]['id']));
        $this->assertNotNull($this->index->findEvent($inserted[1]['id']));
    }

    public function test_audit_trail_is_immutable(): void
    {
        $record = \App\Services\AuditService::record('test.immutability', 'system', '1');
        $this->assertNotNull($record);

        $this->expectException(LogicException::class);
        $record->update(['action' => 'tampered.action']);
    }
}
