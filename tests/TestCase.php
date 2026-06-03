<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider as TwoFactorAuthenticationProviderContract;
use Laravel\Fortify\TwoFactorAuthenticationProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use Padosoft\Rebel\Bridge\Fortify\Contracts\PasskeyConfirmer;
use Padosoft\Rebel\Bridge\Fortify\RebelFortifyBridgeServiceProvider;
use Padosoft\Rebel\Bridge\Fortify\Testing\FakePasskeyConfirmer;
use Padosoft\Rebel\Core\RebelCoreServiceProvider;
use Padosoft\Rebel\EmailOtp\RebelEmailOtpServiceProvider;
use Padosoft\Rebel\StepUp\RebelStepUpServiceProvider;
use PragmaRX\Google2FA\Google2FA;

abstract class TestCase extends Orchestra
{
    /**
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            RebelCoreServiceProvider::class,
            RebelEmailOtpServiceProvider::class,
            RebelStepUpServiceProvider::class,
            RebelFortifyBridgeServiceProvider::class,
        ];
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('rebel-core.peppers', [1 => 'test-pepper']);
        $app['config']->set('rebel-core.pepper_current', 1);

        // TOTP engine (normally bound by Fortify's own provider).
        $app->singleton(
            TwoFactorAuthenticationProviderContract::class,
            fn () => new TwoFactorAuthenticationProvider(new Google2FA),
        );

        // Passkey confirmer: a fake so the passkey step-up driver registers in tests.
        $app->singleton(PasskeyConfirmer::class, fn () => new FakePasskeyConfirmer);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../vendor/padosoft/laravel-rebel-core/database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../vendor/padosoft/laravel-rebel-step-up/database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../vendor/padosoft/laravel-rebel-email-otp/database/migrations');

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('email')->nullable();
            $table->string('password')->nullable();
            $table->text('two_factor_secret')->nullable();
            $table->text('two_factor_recovery_codes')->nullable();
            $table->timestamps();
        });
    }
}
