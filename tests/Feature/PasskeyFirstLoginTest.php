<?php

declare(strict_types=1);

use Padosoft\Rebel\Bridge\Fortify\PasskeyFirstLogin;
use Padosoft\Rebel\Bridge\Fortify\Testing\FakePasskeyAuthenticator;
use Padosoft\Rebel\Bridge\Fortify\Tests\Fixtures\User;
use Padosoft\Rebel\Core\Contracts\AuditLogger;
use Padosoft\Rebel\Core\Models\RebelAuthEvent;

function passkeyFirstLogin(User $user): PasskeyFirstLogin
{
    $authenticator = new FakePasskeyAuthenticator(
        user: $user,
        withPasskey: ['has-passkey@example.com'],
        expectedAssertion: 'ok-assertion',
        challenge: 'chal-1',
    );

    return new PasskeyFirstLogin($authenticator, app(AuditLogger::class));
}

it('offers passkey options when available and signals fallback otherwise', function (): void {
    $login = passkeyFirstLogin(User::create(['email' => 'has-passkey@example.com']));

    expect($login->begin('has-passkey@example.com'))->not->toBeNull()
        ->and($login->shouldFallBack('has-passkey@example.com'))->toBeFalse()
        ->and($login->begin('no-passkey@example.com'))->toBeNull()
        ->and($login->shouldFallBack('no-passkey@example.com'))->toBeTrue();
});

it('completes login from a valid assertion bound to the challenge and audits it', function (): void {
    $user = User::create(['email' => 'has-passkey@example.com']);
    $login = passkeyFirstLogin($user);

    expect($login->complete('ok-assertion', 'chal-1'))->toBe($user)
        // Wrong assertion or wrong challenge both fail (replay-resistant).
        ->and($login->complete('bad-assertion', 'chal-1'))->toBeNull()
        ->and($login->complete('ok-assertion', 'wrong-challenge'))->toBeNull();

    $success = RebelAuthEvent::query()->where('event_type', 'login.succeeded')->first();
    expect($success)->not->toBeNull()
        ->and($success?->subject_id)->toBe((string) $user->getKey())
        ->and(RebelAuthEvent::query()->where('event_type', 'login.failed')->count())->toBe(2);
});
