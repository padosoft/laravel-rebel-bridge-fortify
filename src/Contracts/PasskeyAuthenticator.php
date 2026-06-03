<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Padosoft\Rebel\Bridge\Fortify\Testing\FakePasskeyAuthenticator;

/**
 * Drives a passkey-first LOGIN (as opposed to {@see PasskeyConfirmer}, which
 * re-confirms an already-known user). Here we do not yet know who the user is: we
 * offer passkey options for an identifier and resolve the subject from the
 * resulting assertion.
 *
 * Bind your own WebAuthn-backed implementation; a
 * {@see FakePasskeyAuthenticator} ships for tests.
 */
interface PasskeyAuthenticator
{
    /**
     * Public-key request options for this identifier (email/username), or null when
     * the identifier has no usable passkey — in which case the caller should fall
     * back to another method (e.g. email-OTP).
     *
     * The options MUST embed a single-use server challenge; persist it (e.g. in the
     * session) and pass it back to {@see verify()} so the assertion is bound to it.
     *
     * @return array<string, mixed>|null
     */
    public function options(string $identifier): ?array;

    /**
     * Verify an assertion AGAINST the challenge previously issued by {@see options()}
     * and return the authenticated user, or null on failure. Binding the assertion to
     * the challenge is what makes the flow replay-resistant.
     */
    public function verify(string $assertion, string $challenge): ?Authenticatable;
}
