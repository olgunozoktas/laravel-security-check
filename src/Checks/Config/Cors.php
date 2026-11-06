<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Config;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** CORS that lets every origin read answers, worst with credentials. */
final class Cors extends BaseCheck
{
    public function group(): string { return 'config'; }

    public function applies(Context $context): bool
    {
        return is_array($context->config('cors'));
    }

    public function run(Context $context): array
    {
        $origins = (array) $context->config('cors.allowed_origins', []);
        if (! in_array('*', $origins, true)) {
            return [];
        }
        if ($context->config('cors.supports_credentials')) {
            return [$this->finding(Severity::High, 'CORS allows every origin (*) with credentials: any site can read the answers of a logged-in user.', 'Name the allowed origins in config/cors.php (allowed_origins), or set supports_credentials to false.', 'config/cors.php')];
        }

        return [$this->finding(Severity::Low, 'CORS allows every origin (*) for '.implode(', ', (array) $context->config('cors.paths', [])).'.', 'Name the origins that need it in config/cors.php, unless the API is public on purpose.', 'config/cors.php')];
    }
}
