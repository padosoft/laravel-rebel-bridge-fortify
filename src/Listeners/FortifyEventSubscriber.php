<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;
use Padosoft\Rebel\Core\Audit\AuditEvent;
use Padosoft\Rebel\Core\Audit\AuthEventType;
use Padosoft\Rebel\Core\Contracts\AuditLogger;
use Padosoft\Rebel\Core\Contracts\KeyedHasher;

/**
 * Maps framework + Fortify authentication events into the Rebel audit trail, so
 * logins, failures, lockouts and two-factor lifecycle events all land in one place
 * (`rebel_auth_events`) regardless of which library produced them.
 *
 * Framework auth events (Login/Failed/Logout/Lockout) are always wired; the Fortify
 * two-factor events are wired by the service provider only when Fortify is installed.
 */
final class FortifyEventSubscriber
{
    public function __construct(
        private readonly AuditLogger $audit,
        private readonly KeyedHasher $hasher,
    ) {}

    public function handleLogin(Login $event): void
    {
        $this->record(AuthEventType::LoginSucceeded->value, $event->guard, $event->user);
    }

    public function handleFailed(Failed $event): void
    {
        $this->record(AuthEventType::LoginFailed->value, $event->guard, $event->user);
    }

    public function handleLogout(Logout $event): void
    {
        $this->record(AuthEventType::Logout->value, $event->guard, $event->user);
    }

    public function handleLockout(Lockout $event): void
    {
        // Keep the lockout attributable for incident response, but store IP and
        // identifier as keyed HMACs (never plaintext PII) like the rest of the suite.
        $ip = $event->request->ip();
        $email = $event->request->input('email');

        $identifier = is_string($email) && $email !== '' ? $this->hasher->hash($email) : null;
        $ipHash = $ip !== null && $ip !== '' ? $this->hasher->hash($ip) : null;

        $keyVersion = $identifier?->keyVersion;

        if ($keyVersion === null) {
            $keyVersion = $ipHash?->keyVersion;
        }

        $this->audit->record(new AuditEvent(
            type: 'login.lockout',
            identifierHmac: $identifier?->hash,
            keyVersion: $keyVersion,
            ipHmac: $ipHash?->hash,
        ));
    }

    public function handleTwoFactorChallenged(object $event): void
    {
        $this->record('fortify.two_factor.challenged', null, $this->userOf($event));
    }

    public function handleTwoFactorEnabled(object $event): void
    {
        $this->record('fortify.two_factor.enabled', null, $this->userOf($event));
    }

    public function handleTwoFactorDisabled(object $event): void
    {
        $this->record('fortify.two_factor.disabled', null, $this->userOf($event));
    }

    public function handleValidTwoFactorCode(object $event): void
    {
        $this->record('fortify.two_factor.verified', null, $this->userOf($event), ['otp', 'totp']);
    }

    public function handleRecoveryCodeReplaced(object $event): void
    {
        $this->record('fortify.recovery_code.used', null, $this->userOf($event), ['recovery_code']);
    }

    /**
     * @param  list<string>|null  $amr
     */
    private function record(string $type, ?string $guard, ?Authenticatable $user, ?array $amr = null): void
    {
        $id = $user?->getAuthIdentifier();

        $this->audit->record(new AuditEvent(
            type: $type,
            guard: $guard,
            subjectType: $user !== null ? $user::class : null,
            subjectId: is_scalar($id) ? (string) $id : null,
            amr: $amr,
        ));
    }

    /** Best-effort extraction of a `$user` public property from a Fortify event. */
    private function userOf(object $event): ?Authenticatable
    {
        $user = get_object_vars($event)['user'] ?? null;

        return $user instanceof Authenticatable ? $user : null;
    }
}
