<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Config;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** Debug tools that show queries, requests and sessions: in `require` they ship to production. */
final class DevToolsInProduction extends BaseCheck
{
    private const TOOLS = ['barryvdh/laravel-debugbar' => 'Debugbar', 'fruitcake/laravel-debugbar' => 'Debugbar', 'beyondcode/laravel-query-detector' => 'Query Detector', 'itsgoingd/clockwork' => 'Clockwork'];

    public function group(): string { return 'config'; }

    public function run(Context $context): array
    {
        $out = [];
        $required = $context->requiredPackages();
        foreach (self::TOOLS as $package => $label) {
            if (in_array($package, $required, true)) {
                $out[] = $this->finding(Severity::Medium, "$label ($package) is in composer.json's require, so it is installed in production too.", "Move it to require-dev: composer remove $package && composer require --dev $package.", 'composer.json');
            }
        }
        if ($context->production() && $context->config('telescope.enabled') && ! $context->config('telescope.gate_checked', false)) {
            $out[] = $this->finding(Severity::Low, 'Telescope is on in production: it records requests, queries and sessions.', 'Check that TelescopeServiceProvider::gate() lets in only your own staff, or set TELESCOPE_ENABLED=false.', 'app/Providers/TelescopeServiceProvider.php');
        }

        return $out;
    }
}
