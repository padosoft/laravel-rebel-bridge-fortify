<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify\Drivers;

use Illuminate\Contracts\Hashing\Hasher;
use Padosoft\Rebel\Core\Assurance\Aal;
use Padosoft\Rebel\Core\Assurance\AssuranceLevel;
use Padosoft\Rebel\StepUp\Contracts\StepUpDriver;
use Padosoft\Rebel\StepUp\StepUpContext;

/**
 * Step-up driver that re-confirms the user's password (the "are you sure it's you?"
 * pattern, like Fortify's password confirmation / GitHub's sudo mode).
 *
 * Assurance: this is a SINGLE knowledge factor, so per NIST it is **AAL1** and NOT
 * phishing-resistant. Do not use it to satisfy high-assurance purposes — for those
 * prefer TOTP ({@see TotpStepUpDriver}) or, best, a passkey
 * ({@see PasskeyConfirmStepUpDriver}). It is best used as a web/session re-auth gate.
 */
final class PasswordConfirmStepUpDriver implements StepUpDriver
{
    public function __construct(private readonly Hasher $hasher) {}

    public function key(): string
    {
        return 'fortify_password_confirm';
    }

    public function assurance(): AssuranceLevel
    {
        return new AssuranceLevel(Aal::Aal1, phishingResistant: false, amr: ['pwd']);
    }

    public function isAvailableFor(StepUpContext $context): bool
    {
        return $this->passwordHash($context) !== null;
    }

    public function start(StepUpContext $context): ?string
    {
        // Nothing to send: the user already knows their password.
        return null;
    }

    public function verify(StepUpContext $context, string $input, ?string $reference): bool
    {
        $hash = $this->passwordHash($context);

        return $hash !== null && $this->hasher->check($input, $hash);
    }

    private function passwordHash(StepUpContext $context): ?string
    {
        $password = $context->subject->getAuthPassword();

        // A user without a usable password (e.g. passwordless-only account) cannot
        // confirm via this driver.
        return $password === '' ? null : $password;
    }
}
