<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Config;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** APP_DEBUG on outside local and testing shows stack traces, config and SQL to every visitor. */
final class DebugMode extends BaseCheck
{
    public function group(): string { return 'config'; }

    public function run(Context $context): array
    {
        if (! $context->config('app.debug') || in_array($context->environment(), ['local', 'testing'], true)) {
            return [];
        }

        return [$this->finding($context->production() ? Severity::High : Severity::Medium,
            "APP_DEBUG is on in the {$context->environment()} environment: an error page shows the stack trace, the config and the SQL.",
            'Set APP_DEBUG=false in that environment\'s .env, then run php artisan config:cache.', '.env')];
    }
}
