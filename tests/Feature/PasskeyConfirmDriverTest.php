<?php

declare(strict_types=1);

use Padosoft\Rebel\Bridge\Fortify\Drivers\PasskeyConfirmStepUpDriver;
use Padosoft\Rebel\Bridge\Fortify\Testing\FakePasskeyConfirmer;
use Padosoft\Rebel\Bridge\Fortify\Tests\Fixtures\User;
use Padosoft\Rebel\Core\Assurance\Aal;

it('binds the assertion to a server-issued challenge and rejects unbound/forged ones', function (): void {
    $driver = new PasskeyConfirmStepUpDriver(new FakePasskeyConfirmer(
        registered: true,
        expectedAssertion: 'good-assertion',
        challenge: 'chal-1',
    ));
    $ctx = bridgeCtx(User::create(['email' => 'a@b.it']));

    $reference = $driver->start($ctx);

    expect($driver->isAvailableFor($ctx))->toBeTrue()
        ->and($reference)->toBe('chal-1')
        ->and($driver->verify($ctx, 'good-assertion', $reference))->toBeTrue()
        // No bound challenge ⇒ refuse (replay-safe).
        ->and($driver->verify($ctx, 'good-assertion', null))->toBeFalse()
        // Wrong challenge ⇒ refuse.
        ->and($driver->verify($ctx, 'good-assertion', 'other-challenge'))->toBeFalse()
        // Forged assertion ⇒ refuse.
        ->and($driver->verify($ctx, 'forged', $reference))->toBeFalse();
});

it('is not available when the user has no registered passkey', function (): void {
    $driver = new PasskeyConfirmStepUpDriver(new FakePasskeyConfirmer(registered: false));

    expect($driver->isAvailableFor(bridgeCtx(User::create(['email' => 'a@b.it']))))->toBeFalse()
        ->and($driver->start(bridgeCtx(User::create(['email' => 'c@d.it']))))->toBeNull();
});

it('declares AAL2 and is phishing-resistant (strongest factor)', function (): void {
    $assurance = (new PasskeyConfirmStepUpDriver(new FakePasskeyConfirmer))->assurance();

    expect($assurance->aal)->toBe(Aal::Aal2)
        ->and($assurance->phishingResistant)->toBeTrue();
});
