<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use Padosoft\Rebel\Bridge\Fortify\Contracts\PasskeyAuthenticator;

/**
 * Deterministic {@see PasskeyAuthenticator} for tests.
 *
 * - identifiers in {@see $withPasskey} get non-null options;
 * - the {@see $expectedAssertion} resolves to {@see $user}.
 */
final class FakePasskeyAuthenticator implements PasskeyAuthenticator
{
    /**
     * @param  list<string>  $withPasskey
     */
    public function __construct(
        public ?Authenticatable $user = null,
        public array $withPasskey = [],
        public string $expectedAssertion = 'valid-assertion',
        public string $challenge = 'fake-challenge',
    ) {}

    public function options(string $identifier): ?array
    {
        return in_array($identifier, $this->withPasskey, true)
            ? ['challenge' => $this->challenge, 'identifier' => $identifier]
            : null;
    }

    public function verify(string $assertion, string $challenge): ?Authenticatable
    {
        return hash_equals($this->expectedAssertion, $assertion) && hash_equals($this->challenge, $challenge)
            ? $this->user
            : null;
    }
}
