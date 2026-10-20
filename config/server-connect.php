<?php

return [
    // Seconds for the TCP connection and the SSH handshake together (at least 1).
    'connect_timeout' => max(1, (int) env('SERVER_CONNECT_TIMEOUT', 8)),

    // Keepalive interval in seconds, so a dead connection is noticed (at least 1).
    'keepalive' => max(1, (int) env('SERVER_CONNECT_KEEPALIVE', 5)),

    // Refuse RSA host keys shorter than this many bits.
    'min_rsa_bits' => max(1024, (int) env('SERVER_CONNECT_MIN_RSA_BITS', 2048)),

    // Output kept per command, in bytes; the rest still streams to the caller.
    'max_output_bytes' => max(65536, (int) env('SERVER_CONNECT_MAX_OUTPUT_BYTES', 4 * 1024 * 1024)),

    // Allow loopback and this machine's own addresses as targets.
    'allow_local' => filter_var(env('SERVER_CONNECT_ALLOW_LOCAL', false), FILTER_VALIDATE_BOOLEAN),

    // Allow private networks (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7).
    // Leave off in a multi-tenant app: users could reach your internal network.
    'allow_private' => filter_var(env('SERVER_CONNECT_ALLOW_PRIVATE', false), FILTER_VALIDATE_BOOLEAN),

    // Host names or IPs this application is reached at (refused as targets).
    // APP_URL's host and this machine's interface addresses are always included.
    'own_hosts' => array_values(array_filter(array_map('trim', explode(',', (string) env('SERVER_CONNECT_OWN_HOSTS', ''))))),
];
