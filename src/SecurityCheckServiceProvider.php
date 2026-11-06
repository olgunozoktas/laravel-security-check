<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck;

use Illuminate\Support\ServiceProvider;
use Olgun\SecurityCheck\Console\SecurityCheckCommand;

final class SecurityCheckServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security-check.php', 'security-check');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([SecurityCheckCommand::class]);
            $this->publishes([__DIR__.'/../config/security-check.php' => config_path('security-check.php')], 'security-check-config');
        }
    }
}
