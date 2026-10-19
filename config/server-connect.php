<?php

return [
    // Seconds to wait for the TCP connection and the SSH handshake.
    'connect_timeout' => (int) env('SERVER_CONNECT_TIMEOUT', 8),

    // Keepalive interval in seconds, so a dead connection is noticed.
    'keepalive' => (int) env('SERVER_CONNECT_KEEPALIVE', 5),

    // Allow loopback and this application's own address as targets.
    'allow_local' => (bool) env('SERVER_CONNECT_ALLOW_LOCAL', false),

    // Host names or IPs this application is reached at (refused as targets).
    // APP_URL's host is always included.
    'own_hosts' => array_filter(explode(',', (string) env('SERVER_CONNECT_OWN_HOSTS', ''))),
];
