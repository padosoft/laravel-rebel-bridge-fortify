<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify\Drivers;

use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Database\Eloquent\Model;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;
use Padosoft\Rebel\Core\Assurance\Aal;
use Padosoft\Rebel\Core\Assurance\AssuranceLevel;
use Padosoft\Rebel\Core\Audit\AuditEvent;
use Padosoft\Rebel\Core\Contracts\AuditLogger;
use Padosoft\Rebel\StepUp\Contracts\StepUpDriver;
use Padosoft\Rebel\StepUp\StepUpContext;

/**
 * Step-up driver backed by Fortify's TOTP two-factor authentication (Google
 * Authenticator & friends). It also accepts a single-use **recovery code**.
 *
 * Assurance: **AAL2** (the user already has a session = "something you have/know",
 * plus a TOTP possession factor), NOT phishing-resistant (a TOTP can still be
 * phished in real time — for phishing resistance use a passkey).
 *
 * Replay protection: TOTP verification is delegated to Fortify's
 * {@see TwoFactorAuthenticationProvider}, which (when bound with a cache, the default
 * in a real Fortify install) rejects re-use of an already-consumed time-step. On top
 * of that, every step-up challenge is single-use at the manager level. Recovery codes
 * are consumed atomically (row lock) so they cannot be redeemed twice concurrently.
 *
 * Storage: it reads Fortify's `two_factor_secret` / `two_factor_recovery_codes`
 * attributes (encrypted at rest) directly off the Eloquent model, so it works with
 * any user model using Fortify's `TwoFactorAuthenticatable` trait.
 */
final class TotpStepUpDriver implements StepUpDriver
{
    public function __construct(
        private readonly TwoFactorAuthenticationProvider $provider,
        private readonly Encrypter $encrypter,
        private readonly AuditLogger $audit,
    ) {}

    public function key(): string
    {
        return 'fortify_totp';
    }

    public function assurance(): AssuranceLevel
    {
        return new AssuranceLevel(Aal::Aal2, phishingResistant: false, amr: ['otp', 'totp']);
    }

    public function isAvailableFor(StepUpContext $context): bool
    {
        return $this->secret($context) !== null;
    }

    public function start(StepUpContext $context): ?string
    {
        // Nothing to send: the authenticator app generates the code locally.
        return null;
    }

    public function verify(StepUpContext $context, string $input, ?string $reference): bool
    {
        $secret = $this->secret($context);

        if ($secret === null) {
            return false;
        }

        if ($this->provider->verify($secret, $input)) {
            return true;
        }

        // Fall back to a single-use recovery code.
        return $this->consumeRecoveryCode($context, $input);
    }

    private function secret(StepUpContext $context): ?string
    {
        $subject = $context->subject;

        if (! $subject instanceof Model) {
            return null;
        }

        $raw = $subject->getAttribute('two_factor_secret');

        if (! is_string($raw) || $raw === '') {
            return null;
        }

        try {
            $secret = $this->encrypter->decrypt($raw);
        } catch (\Throwable) {
            return null;
        }

        return is_string($secret) && $secret !== '' ? $secret : null;
    }

    /**
     * Atomically match the input against the stored recovery codes and, if found,
     * consume it (single-use). The whole read-check-write runs inside a transaction
     * with a row lock so two concurrent requests cannot redeem the same code, and the
     * write is a targeted UPDATE (it never flushes other dirty model attributes).
     */
    private function consumeRecoveryCode(StepUpContext $context, string $input): bool
    {
        $subject = $context->subject;

        if (! $subject instanceof Model) {
            return false;
        }

        $consumed = $subject->getConnection()->transaction(function () use ($subject, $input): bool {
            $locked = $subject->newQuery()->lockForUpdate()->find($subject->getKey());

            if (! $locked instanceof Model) {
                return false;
            }

            $codes = $this->recoveryCodes($locked);

            if ($codes === null) {
                return false;
            }

            $remaining = [];
            $matched = false;

            foreach ($codes as $code) {
                if (! $matched && hash_equals($code, $input)) {
                    $matched = true;

                    continue;
                }

                $remaining[] = $code;
            }

            if (! $matched) {
                return false;
            }

            $encrypted = $this->encrypter->encrypt(json_encode($remaining, JSON_THROW_ON_ERROR));

            $locked->newQuery()
                ->where($locked->getKeyName(), $locked->getKey())
                ->update(['two_factor_recovery_codes' => $encrypted]);

            return true;
        });

        if ($consumed) {
            $this->auditRecoveryCodeUse($context);
        }

        return $consumed;
    }

    /**
     * Decrypt and decode the user's recovery codes into a list of strings, or null
     * when absent/unreadable.
     *
     * @return list<string>|null
     */
    private function recoveryCodes(Model $user): ?array
    {
        $raw = $user->getAttribute('two_factor_recovery_codes');

        if (! is_string($raw) || $raw === '') {
            return null;
        }

        try {
            $decoded = $this->encrypter->decrypt($raw);
        } catch (\Throwable) {
            return null;
        }

        if (! is_string($decoded)) {
            return null;
        }

        /** @var mixed $codes */
        $codes = json_decode($decoded, true);

        if (! is_array($codes)) {
            return null;
        }

        return array_values(array_filter($codes, 'is_string'));
    }

    private function auditRecoveryCodeUse(StepUpContext $context): void
    {
        $id = $context->subject->getAuthIdentifier();

        $this->audit->record(new AuditEvent(
            type: 'fortify.recovery_code.used',
            subjectType: $context->subject::class,
            subjectId: is_scalar($id) ? (string) $id : null,
            channel: 'totp',
            amr: ['recovery_code'],
        ));
    }
}
