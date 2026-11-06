<?php

return [
    // The app's own checks: one class in this folder (and namespace) for each check, found on disk.
    'checks_path' => 'app/SecurityChecks',
    'checks_namespace' => 'App\\SecurityChecks',

    // State-changing routes that are public on purpose (a webhook, a login form): URI patterns, as Str::is() reads them.
    'public_routes' => [
        'login', 'register', 'logout', 'forgot-password', 'reset-password', 'reset-password/*', 'two-factor-challenge',
        'livewire/*', 'livewire-*/*', 'broadcasting/auth', 'sanctum/csrf-cookie', '*webhook*', 'stripe/*', 'email/verification-notification',
    ],

    // Blade output that is HTML on purpose: the text inside {!! !!}, as a regular expression.
    'safe_raw_output' => '/^(csrf_field\(\)|method_field\(.*\)|\$slot|\$attributes.*|\$__env->.*|\$component->.*)$/',
];
