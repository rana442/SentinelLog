<?php

namespace App\Services;

use App\Models\AuthorizedSubnet;
use App\Models\LogSource;
use App\Models\SystemSetting;

class RsyslogConfigService
{
    public static function validateCidrOrIp(string $cidr): ?string
    {
        $cidr = trim($cidr);
        if (filter_var($cidr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $cidr;
        }

        if (preg_match('#^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$#', $cidr, $m)) {
            $ip = $m[1];
            $prefix = (int) $m[2];
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $prefix < 1 || $prefix > 32) {
                return null;
            }
            // Normalize host bits to network address so rsyslog $AllowedSender never complains
            $ipLong = ip2long($ip);
            $mask = $prefix === 32 ? -1 : (~((1 << (32 - $prefix)) - 1));
            $netIp = long2ip($ipLong & $mask);
            return $prefix === 32 ? $netIp : "{$netIp}/{$prefix}";
        }

        return null;
    }

    public static function syncAllowedSenders(): bool
    {
        $restrict = (string) SystemSetting::getValue('restrict_unauthorized_sources', '1') === '1';

        $cidrs = ['127.0.0.0/8'];
        foreach (AuthorizedSubnet::where('is_active', true)->pluck('cidr') as $rawCidr) {
            $valid = self::validateCidrOrIp($rawCidr);
            if ($valid) {
                $cidrs[] = $valid;
            }
        }

        foreach (LogSource::where('is_enabled', true)->pluck('ip_address') as $ip) {
            $valid = self::validateCidrOrIp($ip);
            if ($valid) {
                $cidrs[] = $valid;
            }
        }

        $cidrs = array_values(array_unique($cidrs));
        $list = implode(', ', $cidrs);

        $lines = [
            '# Managed by SentinelLog Central Syslog Portal',
            '# Generated at ' . now()->toIso8601String(),
        ];

        if ($restrict && !empty($cidrs)) {
            $lines[] = '$AllowedSender UDP, ' . $list;
            $lines[] = '$AllowedSender TCP, ' . $list;
        } else {
            $lines[] = '# Source restriction disabled in portal settings (accepting from any firewall-permitted host)';
        }

        $content = implode("\n", $lines) . "\n";
        $stagedFile = '/var/lib/central-syslog/allowed_senders.staged';
        @file_put_contents($stagedFile, $content);

        if (is_executable('/opt/central-syslog/scripts/sync-allowed-senders.sh')) {
            exec('sudo -n /opt/central-syslog/scripts/sync-allowed-senders.sh 2>&1', $out, $code);
            return $code === 0;
        }

        return false;
    }
}
