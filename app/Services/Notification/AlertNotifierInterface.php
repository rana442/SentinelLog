<?php

namespace App\Services\Notification;

use App\Models\AlertIncident;
use App\Models\AlertRule;

interface AlertNotifierInterface
{
    public function channelName(): string;

    public function send(AlertIncident $incident, ?AlertRule $rule = null): bool;
}
