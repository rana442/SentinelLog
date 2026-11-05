<?php

return [
    'index_db' => env('SYSLOG_INDEX_DB', '/var/lib/central-syslog/index/syslog_hot.sqlite'),
    'stream_file' => env('SYSLOG_STREAM_FILE', '/var/log/central-syslog/ingest/stream.ndjson'),
    'hosts_dir' => env('SYSLOG_HOSTS_DIR', '/var/log/central-syslog/hosts'),
    'allowed_conf' => env('SYSLOG_ALLOWED_CONF', '/etc/rsyslog.d/15-allowed-senders.conf'),
    'severities' => [
        0 => ['name' => 'emerg', 'label' => 'Emergency', 'badge' => 'red'],
        1 => ['name' => 'alert', 'label' => 'Alert', 'badge' => 'red'],
        2 => ['name' => 'crit', 'label' => 'Critical', 'badge' => 'rose'],
        3 => ['name' => 'err', 'label' => 'Error', 'badge' => 'orange'],
        4 => ['name' => 'warning', 'label' => 'Warning', 'badge' => 'amber'],
        5 => ['name' => 'notice', 'label' => 'Notice', 'badge' => 'cyan'],
        6 => ['name' => 'info', 'label' => 'Informational', 'badge' => 'emerald'],
        7 => ['name' => 'debug', 'label' => 'Debug', 'badge' => 'slate'],
    ],
    'roles' => [
        'super_admin' => 'Super Admin',
        'administrator' => 'Administrator',
        'security_analyst' => 'Security Analyst',
        'read_only' => 'Read Only',
    ],
];
