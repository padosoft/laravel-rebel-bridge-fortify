<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify\Drivers;

use Padosoft\Rebel\Bridge\Fortify\Contracts\PasskeyConfirmer;
use Padosoft\Rebel\Core\Assurance\Aal;
use Padosoft\Rebel\Core\Assurance\AssuranceLevel;
use Padosoft\Rebel\StepUp\Contracts\StepUpDriver;
use Padosoft\Rebel\StepUp\StepUpContext;

/**
 * Step-up driver backed by a passkey / FIDO2 credential.
 *
 * Assurance: **AAL2 and phishing-resistant** — this is the strongest step-up
 * factor and the right choice for high-value purposes (e.g. confirming a
 * credit-order checkout). Verification is delegated to a {@see PasskeyConfirmer}
 * bound by the application.
 */
final class PasskeyConfirmStepUpDriver implements StepUpDriver
{
    public function __construct(private readonly PasskeyConfirmer $confirmer) {}

    public function key(): string
    {
        return 'fortify_passkey_confirm';
    }

    public function assurance(): AssuranceLevel
    {
        return new AssuranceLevel(Aal::Aal2, phishingResistant: true, amr: ['webauthn']);
    }

    public function isAvailableFor(StepUpContext $context): bool
    {
        return $this->confirmer->isRegisteredFor($context->subject);
    }

    public function start(StepUpContext $context): ?string
    {
        if (! $this->confirmer->isRegisteredFor($context->subject)) {
            return null;
        }

        // Issue and store a single-use challenge: the assertion is later verified
        // against THIS challenge, so a captured assertion cannot be replayed.
        return $this->confirmer->newChallenge($context->subject);
    }

    public function verify(StepUpContext $context, string $input, ?string $reference): bool
    {
        // No bound challenge ⇒ refuse (replay-safe): a passkey confirm must always be
        // tied to the nonce issued in start().
        if ($reference === null || $reference === '') {
            return false;
        }

        return $this->confirmer->confirm($context->subject, $input, $reference);
    }
}
