<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use Padosoft\Rebel\Bridge\Fortify\Tests\Fixtures\User;
use Padosoft\Rebel\StepUp\DriverRegistry;
use Padosoft\Rebel\StepUp\RebelStepUp;

it('registers the Fortify-backed drivers into the step-up registry', function (): void {
    $registry = app(DriverRegistry::class);

    expect($registry->get('fortify_password_confirm'))->not->toBeNull()
        ->and($registry->get('fortify_totp'))->not->toBeNull()
        ->and($registry->get('fortify_passkey_confirm'))->not->toBeNull();
});

it('confirms a step-up end-to-end via the Fortify password driver', function (): void {
    config()->set('rebel-step-up.purposes.reauth', [
        'required_assurance' => 'aal1',
        'drivers' => ['fortify_password_confirm'],
        'always_require' => true,
    ]);

    $user = User::create(['email' => 'a@b.it', 'password' => Hash::make('pw123!')]);
    $stepUp = app(RebelStepUp::class);
    $ctx = bridgeCtx($user, 'reauth');

    $start = $stepUp->start($ctx);

    expect($start->driver)->toBe('fortify_password_confirm')
        ->and($stepUp->confirm($start->challengeId, 'pw123!', $ctx)->success)->toBeTrue()
        ->and($stepUp->isConfirmed($ctx))->toBeTrue();

    // A wrong password must NOT confirm.
    $other = bridgeCtx(User::create(['email' => 'c@d.it', 'password' => Hash::make('zzz')]), 'reauth');
    $otherStart = $stepUp->start($other);
    expect($stepUp->confirm($otherStart->challengeId, 'WRONG', $other)->success)->toBeFalse();
});
