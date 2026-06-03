<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use Padosoft\Rebel\Bridge\Fortify\Contracts\PasskeyConfirmer;

/**
 * Deterministic {@see PasskeyConfirmer} for tests: configurable registration state,
 * a fixed challenge, and a fixed "valid" assertion. Confirmation succeeds only when
 * BOTH the assertion and the bound challenge match (mirroring real replay binding).
 */
final class FakePasskeyConfirmer implements PasskeyConfirmer
{
    public function __construct(
        public bool $registered = true,
        public string $expectedAssertion = 'valid-assertion',
        public string $challenge = 'fake-challenge',
    ) {}

    public function isRegisteredFor(Authenticatable $user): bool
    {
        return $this->registered;
    }

    public function newChallenge(Authenticatable $user): string
    {
        return $this->challenge;
    }

    public function confirm(Authenticatable $user, string $assertion, string $challenge): bool
    {
        return hash_equals($this->challenge, $challenge)
            && hash_equals($this->expectedAssertion, $assertion);
    }
}
