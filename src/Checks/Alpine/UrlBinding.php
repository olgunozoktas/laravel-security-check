<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Alpine;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** An Alpine-bound href, src or action: a "javascript:" URL in the value runs code on a click (the reviewer's `bind-url-no-scheme-check`). */
final class UrlBinding extends AlpineCheck
{
    public function run(Context $context): array
    {
        $out = [];
        foreach ($context->files->grep($context->bladeFiles(), '/(?:x-bind:|(?<![\w-]):)(?:href|src|action|formaction)\s*=\s*["\'][^"\']+["\']/') as [$file, $line, $code]) {
            preg_match('/(?:x-bind:|(?<![\w-]):)(?:href|src|action|formaction)\s*=\s*["\'][^"\']+["\']/', $code, $m);
            if (AlpineSource::looksLikePhp($m[0]) || preg_match('/=\s*["\']\s*[\'`]/', $m[0]) === 1) {
                continue;  // a Blade binding, or a literal string
            }
            $out[] = $this->finding(Severity::Low, 'An Alpine-bound URL: a "javascript:" value in it runs code when it is clicked.',
                'Allow only http(s) (and relative) URLs for the value, on the server; never bind a URL that a user typed without that check.', $file, $line, $m[0]);
        }

        return $out;
    }
}
