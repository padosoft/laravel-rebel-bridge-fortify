<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify;

use Illuminate\Contracts\Auth\Authenticatable;
use Padosoft\Rebel\Bridge\Fortify\Contracts\PasskeyAuthenticator;
use Padosoft\Rebel\Core\Audit\AuditEvent;
use Padosoft\Rebel\Core\Audit\AuthEventType;
use Padosoft\Rebel\Core\Contracts\AuditLogger;

/**
 * Orchestrates a **passkey-first** login flow:
 *
 *   1. begin($identifier) → if the user has a passkey, return its request options
 *      (let the browser produce an assertion); if not, return null so the caller
 *      falls back to email-OTP (or any other configured method).
 *   2. complete($assertion) → verify the assertion and return the authenticated user.
 *
 * The actual WebAuthn work is delegated to a {@see PasskeyAuthenticator}; this class
 * only owns the "try passkey, else fall back" decision and the audit trail.
 */
final class PasskeyFirstLogin
{
    /** @var array<string, array<string, mixed>|null> */
    private array $optionsCache = [];

    public function __construct(
        private readonly PasskeyAuthenticator $authenticator,
        private readonly AuditLogger $audit,
    ) {}

    /**
     * Begin login for an identifier. Returns passkey options, or null when no passkey
     * is available (the caller should then fall back, e.g. to email-OTP).
     *
     * Memoized per identifier so that calling begin()/shouldFallBack() more than once
     * in the same request does NOT make a real authenticator issue (and persist) a new
     * single-use challenge each time — which would invalidate the challenge the browser
     * already holds.
     *
     * @return array<string, mixed>|null
     */
    public function begin(string $identifier): ?array
    {
        if (! array_key_exists($identifier, $this->optionsCache)) {
            $this->optionsCache[$identifier] = $this->authenticator->options($identifier);
        }

        return $this->optionsCache[$identifier];
    }

    /** True when the identifier has no passkey and the caller should fall back. */
    public function shouldFallBack(string $identifier): bool
    {
        return $this->begin($identifier) === null;
    }

    /**
     * Complete login from a passkey assertion, bound to the challenge issued by
     * {@see begin()}. Returns the user, or null on failure.
     */
    public function complete(string $assertion, string $challenge): ?Authenticatable
    {
        $user = $this->authenticator->verify($assertion, $challenge);
        $id = $user?->getAuthIdentifier();

        $this->audit->record(new AuditEvent(
            type: $user !== null ? AuthEventType::LoginSucceeded->value : AuthEventType::LoginFailed->value,
            subjectType: $user !== null ? $user::class : null,
            subjectId: $user !== null && is_scalar($id) ? (string) $id : null,
            channel: 'passkey',
            // Only claim the WebAuthn factor when it actually succeeded — a failed
            // attempt must not record an AMR (it misleads SIEM/`amr` consumers).
            amr: $user !== null ? ['webauthn'] : null,
            metadata: ['method' => 'passkey_first'],
        ));

        return $user;
    }
}
