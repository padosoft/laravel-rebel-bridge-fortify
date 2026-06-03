<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Padosoft\Rebel\Bridge\Fortify\Contracts\PasskeyConfirmer;
use Padosoft\Rebel\Bridge\Fortify\Drivers\PasskeyConfirmStepUpDriver;
use Padosoft\Rebel\Bridge\Fortify\Drivers\PasswordConfirmStepUpDriver;
use Padosoft\Rebel\Bridge\Fortify\Drivers\TotpStepUpDriver;
use Padosoft\Rebel\Bridge\Fortify\Listeners\FortifyEventSubscriber;
use Padosoft\Rebel\Bridge\Fortify\Support\FortifyBridge;
use Padosoft\Rebel\StepUp\DriverRegistry;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

/**
 * Bridges Laravel Fortify into Laravel Rebel:
 *  - exposes password-confirm / TOTP / passkey as step-up drivers (registered into
 *    the Rebel step-up DriverRegistry);
 *  - maps framework + Fortify auth events into the Rebel audit trail.
 *
 * Everything Fortify-specific is feature-detected: if Fortify is absent the bridge
 * still installs and the password-confirm driver keeps working, while the TOTP
 * driver and the Fortify event mapping are simply skipped.
 */
final class RebelFortifyBridgeServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-rebel-bridge-fortify')
            ->hasConfigFile('rebel-bridge-fortify');
    }

    public function packageBooted(): void
    {
        $this->registerStepUpDrivers();
        $this->registerEventListeners();
    }

    private function registerStepUpDrivers(): void
    {
        $config = $this->app->make(Repository::class);
        $registry = $this->app->make(DriverRegistry::class);

        if ($config->get('rebel-bridge-fortify.drivers.password_confirm', true) === true) {
            $registry->register($this->app->make(PasswordConfirmStepUpDriver::class));
        }

        // TOTP needs Fortify's TwoFactorAuthenticationProvider.
        if ($config->get('rebel-bridge-fortify.drivers.totp', true) === true && FortifyBridge::installed()) {
            $registry->register($this->app->make(TotpStepUpDriver::class));
        }

        // Passkey needs an application-provided PasskeyConfirmer.
        if ($config->get('rebel-bridge-fortify.drivers.passkey', true) === true && $this->app->bound(PasskeyConfirmer::class)) {
            $registry->register($this->app->make(PasskeyConfirmStepUpDriver::class));
        }
    }

    private function registerEventListeners(): void
    {
        $config = $this->app->make(Repository::class);

        if ($config->get('rebel-bridge-fortify.audit_events', true) !== true) {
            return;
        }

        $events = $this->app->make(Dispatcher::class);
        $subscriber = $this->app->make(FortifyEventSubscriber::class);

        // Framework auth events — always available.
        $events->listen(Login::class, [$subscriber, 'handleLogin']);
        $events->listen(Failed::class, [$subscriber, 'handleFailed']);
        $events->listen(Logout::class, [$subscriber, 'handleLogout']);
        $events->listen(Lockout::class, [$subscriber, 'handleLockout']);

        if (! FortifyBridge::installed()) {
            return;
        }

        // Fortify two-factor lifecycle events — referenced by string and guarded so the
        // bridge never hard-depends on Fortify's event classes being present.
        $fortifyEvents = [
            'Laravel\\Fortify\\Events\\TwoFactorAuthenticationChallenged' => 'handleTwoFactorChallenged',
            'Laravel\\Fortify\\Events\\TwoFactorAuthenticationEnabled' => 'handleTwoFactorEnabled',
            'Laravel\\Fortify\\Events\\TwoFactorAuthenticationDisabled' => 'handleTwoFactorDisabled',
            'Laravel\\Fortify\\Events\\ValidTwoFactorAuthenticationCodeProvided' => 'handleValidTwoFactorCode',
            'Laravel\\Fortify\\Events\\RecoveryCodeReplaced' => 'handleRecoveryCodeReplaced',
        ];

        foreach ($fortifyEvents as $eventClass => $handler) {
            if (class_exists($eventClass)) {
                $events->listen($eventClass, [$subscriber, $handler]);
            }
        }
    }
}
