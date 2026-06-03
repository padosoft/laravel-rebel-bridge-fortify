<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * Minimal user model for the bridge tests. Mirrors the columns Fortify uses for
 * two-factor authentication (`two_factor_secret`, `two_factor_recovery_codes`).
 */
class User extends Authenticatable
{
    protected $table = 'users';

    protected $guarded = [];

    public $timestamps = false;
}
