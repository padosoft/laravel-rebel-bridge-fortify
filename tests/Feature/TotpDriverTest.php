<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Crypt;
use Padosoft\Rebel\Bridge\Fortify\Drivers\TotpStepUpDriver;
use Padosoft\Rebel\Bridge\Fortify\Tests\Fixtures\User;
use Padosoft\Rebel\Core\Assurance\Aal;
use PragmaRX\Google2FA\Google2FA;

/** A user whose 2FA secret exists but is NOT confirmed/enabled (Fortify confirm flow). */
class PendingTwoFactorUser extends User
{
    public function hasEnabledTwoFactorAuthentication(): bool
    {
        return false;
    }
}

it('verifies a valid TOTP code and rejects an invalid one', function (): void {
    $google2fa = new Google2FA;
    $secret = $google2fa->generateSecretKey();
    $user = User::create(['email' => 'a@b.it', 'two_factor_secret' => Crypt::encrypt($secret)]);

    $driver = app(TotpStepUpDriver::class);
    $ctx = bridgeCtx($user);

    expect($driver->isAvailableFor($ctx))->toBeTrue()
        ->and($driver->verify($ctx, $google2fa->getCurrentOtp($secret), null))->toBeTrue()
        ->and($driver->verify($ctx, '000000', null))->toBeFalse();
});

it('is not available without a two-factor secret', function (): void {
    $user = User::create(['email' => 'a@b.it']);

    expect(app(TotpStepUpDriver::class)->isAvailableFor(bridgeCtx($user)))->toBeFalse();
});

it('is unavailable when the 2FA secret is enrolled but not yet confirmed', function (): void {
    $secret = (new Google2FA)->generateSecretKey();
    $user = PendingTwoFactorUser::create(['email' => 'a@b.it', 'two_factor_secret' => Crypt::encrypt($secret)]);

    $driver = app(TotpStepUpDriver::class);
    $ctx = bridgeCtx($user);

    // Even a correct current OTP must NOT pass while 2FA is unconfirmed.
    expect($driver->isAvailableFor($ctx))->toBeFalse()
        ->and($driver->verify($ctx, (new Google2FA)->getCurrentOtp($secret), null))->toBeFalse();
});

it('consumes a single-use recovery code', function (): void {
    $secret = (new Google2FA)->generateSecretKey();
    $user = User::create([
        'email' => 'a@b.it',
        'two_factor_secret' => Crypt::encrypt($secret),
        'two_factor_recovery_codes' => Crypt::encrypt(json_encode(['AAAA-BBBB', 'CCCC-DDDD'])),
    ]);

    $driver = app(TotpStepUpDriver::class);
    $ctx = bridgeCtx($user);

    // First use succeeds…
    expect($driver->verify($ctx, 'AAAA-BBBB', null))->toBeTrue()
        // …a second use of the same code fails (single-use).
        ->and($driver->verify($ctx, 'AAAA-BBBB', null))->toBeFalse()
        // …but the other code still works.
        ->and($driver->verify($ctx, 'CCCC-DDDD', null))->toBeTrue();
});

it('declares AAL2 and is not phishing-resistant', function (): void {
    $assurance = app(TotpStepUpDriver::class)->assurance();

    expect($assurance->aal)->toBe(Aal::Aal2)
        ->and($assurance->phishingResistant)->toBeFalse();
});
