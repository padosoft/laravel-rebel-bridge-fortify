<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Http\Request;
use Padosoft\Rebel\Bridge\Fortify\Tests\Fixtures\User;
use Padosoft\Rebel\Core\Models\RebelAuthEvent;

it('maps a framework login event into the Rebel audit trail', function (): void {
    $user = User::create(['email' => 'a@b.it']);

    event(new Login('web', $user, false));

    $row = RebelAuthEvent::query()->where('event_type', 'login.succeeded')->first();
    expect($row)->not->toBeNull()
        ->and($row?->guard)->toBe('web')
        ->and($row?->subject_id)->toBe((string) $user->getKey());
});

it('records ip, user-agent, aal and the pwd factor on a password login', function (): void {
    $user = User::create(['email' => 'a@b.it']);

    $this->app->instance('request', Request::create('/login', 'POST', ['password' => 'secret'], [], [], [
        'REMOTE_ADDR' => '203.0.113.7',
        'HTTP_USER_AGENT' => 'Mozilla/5.0 (Test)',
    ]));

    event(new Login('web', $user, false));

    $row = RebelAuthEvent::query()->where('event_type', 'login.succeeded')->first();
    expect($row)->not->toBeNull()
        ->and($row?->ip_hmac)->not->toBeNull()
        ->and($row?->user_agent_hash)->not->toBeNull()
        ->and($row?->aal?->value)->toBe('aal1')
        ->and((array) $row?->amr)->toContain('pwd');
});

it('maps failed logins and logouts', function (): void {
    $user = User::create(['email' => 'a@b.it']);

    event(new Failed('web', $user, ['email' => 'a@b.it']));
    event(new Logout('web', $user));

    expect(RebelAuthEvent::query()->where('event_type', 'login.failed')->count())->toBe(1)
        ->and(RebelAuthEvent::query()->where('event_type', 'logout')->count())->toBe(1);
});

it('records a lockout with hashed identifier and ip (no plaintext PII)', function (): void {
    event(new Lockout(Request::create('/login', 'POST', ['email' => 'a@b.it'])));

    $row = RebelAuthEvent::query()->where('event_type', 'login.lockout')->first();
    expect($row)->not->toBeNull()
        ->and($row?->identifier_hmac)->not->toBeNull()
        ->and($row?->ip_hmac)->not->toBeNull();
});
