<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Step-up drivers
    |--------------------------------------------------------------------------
    | Which Fortify-backed step-up drivers to register into the Rebel step-up
    | DriverRegistry. Each one is only registered when it can actually work:
    |  - password_confirm: always available (framework hasher);
    |  - totp:    only when Laravel Fortify is installed;
    |  - passkey: only when a PasskeyConfirmer implementation is bound.
    */
    'drivers' => [
        'password_confirm' => env('REBEL_FORTIFY_DRIVER_PASSWORD', true),
        'totp' => env('REBEL_FORTIFY_DRIVER_TOTP', true),
        'passkey' => env('REBEL_FORTIFY_DRIVER_PASSKEY', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit event mapping
    |--------------------------------------------------------------------------
    | When true, framework auth events (Login/Failed/Logout/Lockout) and Fortify
    | two-factor lifecycle events are recorded into the Rebel audit trail.
    */
    'audit_events' => env('REBEL_FORTIFY_AUDIT_EVENTS', true),

];
