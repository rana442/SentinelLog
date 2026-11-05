<?php

namespace App\Services\Notification;

use App\Models\AlertIncident;
use App\Models\AlertRule;
use App\Models\SystemSetting;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class TelegramAlertNotifier implements AlertNotifierInterface
{
    public function channelName(): string
    {
        return 'telegram';
    }

    public function send(AlertIncident $incident, ?AlertRule $rule = null): bool
    {
        $botToken = SystemSetting::getValue('telegram_bot_token', '');
        $chatId = SystemSetting::getValue('telegram_chat_id', '');

        if (!$botToken || !$chatId) {
            Log::info("TelegramAlertNotifier skipped (unconfigured): {$incident->title}");
            return false;
        }

        $text = sprintf(
            "*[SentinelLog %s]*\n*Title:* %s\n*Host:* `%s` (`%s`)\n*Count:* %d\n*Summary:* %s",
            strtoupper($incident->severity),
            $incident->title,
            $incident->source_host ?: 'system',
            $incident->source_ip ?: '-',
            $incident->match_count,
            $incident->summary
        );

        try {
            $resp = Http::timeout(5)->post("https://api.telegram.org/bot{$botToken}/sendMessage", [
                'chat_id' => $chatId,
                'text' => $text,
                'parse_mode' => 'Markdown',
            ]);
            return $resp->successful();
        } catch (\Throwable $e) {
            Log::warning('TelegramAlertNotifier failed: ' . $e->getMessage());
            return false;
        }
    }
}
