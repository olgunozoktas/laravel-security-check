<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Config;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** In production, APP_URL on http:// makes links, redirects and signed URLs plain HTTP. */
final class HttpsInProduction extends BaseCheck
{
    public function group(): string { return 'config'; }

    public function applies(Context $context): bool
    {
        return $context->production();
    }

    public function run(Context $context): array
    {
        $url = (string) $context->config('app.url');

        return str_starts_with($url, 'http://')
            ? [$this->finding(Severity::Medium, "APP_URL is $url in production: generated links and signed URLs use plain HTTP.", 'Set APP_URL to the https:// address (and redirect HTTP to HTTPS on the web server).', '.env')]
            : [];
    }
}
