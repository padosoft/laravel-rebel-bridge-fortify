<?php

declare(strict_types=1);

namespace Padosoft\Rebel\Bridge\Fortify;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

/**
 * Skeleton iniziale di padosoft/laravel-rebel-bridge-fortify. Implementazione in arrivo.
 */
final class RebelFortifyBridgeServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package->name('laravel-rebel-bridge-fortify');
    }
}
