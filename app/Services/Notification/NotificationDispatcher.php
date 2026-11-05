<?php

namespace App\Services\Notification;

use App\Models\AlertIncident;
use App\Models\AlertRule;

class NotificationDispatcher
{
    /** @var array<string, AlertNotifierInterface> */
    protected array $drivers = [];

    public function __construct()
    {
        $this->register(new EmailAlertNotifier());
        $this->register(new TelegramAlertNotifier());
    }

    public function register(AlertNotifierInterface $notifier): void
    {
        $this->drivers[$notifier->channelName()] = $notifier;
    }

    public function dispatch(AlertIncident $incident, ?AlertRule $rule = null): array
    {
        $channels = $rule?->channels ?? ['email'];
        $sent = [];
        foreach ($channels as $ch) {
            if (isset($this->drivers[$ch]) && $this->drivers[$ch]->send($incident, $rule)) {
                $sent[] = $ch;
            }
        }
        return $sent;
    }
}
