<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify\Support;

use Laravel\Fortify\Fortify;

/**
 * Tiny feature-detector for Laravel Fortify.
 *
 * The bridge is installable even when Fortify is absent: in that case the
 * Fortify-backed pieces (TOTP driver, event mapper) simply do not register, and
 * the service provider logs a clear diagnostic instead of crashing.
 */
final class FortifyBridge
{
    /** Is Laravel Fortify installed in this application? */
    public static function installed(): bool
    {
        return class_exists(Fortify::class);
    }
}
