<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Alpine;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** x-html puts its value into innerHTML: an XSS when the value holds anything a user wrote (alpinejs-security, seam A). */
final class XHtml extends AlpineCheck
{
    public function run(Context $context): array
    {
        $out = [];
        foreach ($context->files->grep($context->bladeFiles(), '/\bx-html\s*=/') as [$file, $line, $code]) {
            $out[] = $this->finding(Severity::Medium, 'x-html writes its value into innerHTML: if any part comes from a user, a script runs, and Alpine also compiles any x-* attribute in it.',
                'Use x-text. If HTML is wanted, clean it on the server with an allow-list sanitiser (a deny-list keeps x-init and @click), or put x-ignore on the region.', $file, $line, $code);
        }

        return $out;
    }
}
