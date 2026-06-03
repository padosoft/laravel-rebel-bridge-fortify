<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use Padosoft\Rebel\Bridge\Fortify\Drivers\PasswordConfirmStepUpDriver;
use Padosoft\Rebel\Bridge\Fortify\Tests\Fixtures\User;
use Padosoft\Rebel\Core\Assurance\Aal;

it('confirms a correct password and rejects a wrong one', function (): void {
    $user = User::create(['email' => 'a@b.it', 'password' => Hash::make('s3cret!')]);
    $driver = app(PasswordConfirmStepUpDriver::class);

    expect($driver->isAvailableFor(bridgeCtx($user)))->toBeTrue()
        ->and($driver->verify(bridgeCtx($user), 's3cret!', null))->toBeTrue()
        ->and($driver->verify(bridgeCtx($user), 'wrong', null))->toBeFalse();
});

it('is not available for a user without a password', function (): void {
    $user = User::create(['email' => 'a@b.it']);

    expect(app(PasswordConfirmStepUpDriver::class)->isAvailableFor(bridgeCtx($user)))->toBeFalse();
});

it('declares AAL1 and is not phishing-resistant', function (): void {
    $assurance = app(PasswordConfirmStepUpDriver::class)->assurance();

    expect($assurance->aal)->toBe(Aal::Aal1)
        ->and($assurance->phishingResistant)->toBeFalse();
});
