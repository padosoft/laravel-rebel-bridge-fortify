<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Padosoft\Rebel\Bridge\Fortify\Tests\TestCase;
use Padosoft\Rebel\Core\Context\SecurityContext;
use Padosoft\Rebel\StepUp\StepUpContext;

uses(TestCase::class)->in(__DIR__);

/** Build a StepUpContext for a subject (shared test helper). */
function bridgeCtx(Authenticatable $user, string $purpose = 'reauth'): StepUpContext
{
    return new StepUpContext($user, $purpose, new SecurityContext('r'));
}
