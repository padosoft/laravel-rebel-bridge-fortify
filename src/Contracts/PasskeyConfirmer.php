<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Padosoft\Rebel\Bridge\Fortify\Testing\FakePasskeyConfirmer;

/**
 * Verifies a WebAuthn/passkey assertion for an ALREADY-authenticated user (the
 * step-up case: we know who the user is, we just need a fresh phishing-resistant
 * proof of presence).
 *
 * WebAuthn assertion verification is a stateful challenge/response protocol that
 * depends on your relying-party setup, so the bridge does not hard-code one
 * implementation: bind your own (e.g. backed by Fortify's passkey support or a
 * dedicated WebAuthn package) to this contract in the container. A
 * {@see FakePasskeyConfirmer} ships for tests.
 *
 * IMPORTANT (replay resistance): {@see newChallenge()} issues a single-use,
 * server-side nonce; {@see confirm()} MUST verify the assertion against THAT exact
 * challenge. The step-up driver stores the challenge as its opaque reference and
 * passes it back on verify, so a captured assertion cannot be replayed against a
 * different challenge.
 *
 * When no implementation is bound, the passkey step-up driver is simply not registered.
 */
interface PasskeyConfirmer
{
    /** Does this user have at least one passkey/credential registered? */
    public function isRegisteredFor(Authenticatable $user): bool;

    /**
     * Issue a fresh single-use challenge (nonce) for this user. The returned value is
     * both sent to the browser (to feed `navigator.credentials.get()`) and stored by
     * the step-up driver as its reference.
     */
    public function newChallenge(Authenticatable $user): string;

    /**
     * Verify the assertion (the JSON produced by `navigator.credentials.get()`)
     * against the specific challenge previously issued. Return true on success.
     */
    public function confirm(Authenticatable $user, string $assertion, string $challenge): bool;
}
