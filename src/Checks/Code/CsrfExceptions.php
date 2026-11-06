<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Code;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** URIs taken out of CSRF protection: another site can send a form there with the user's session. */
final class CsrfExceptions extends BaseCheck
{
    public function group(): string { return 'code'; }

    public function run(Context $context): array
    {
        $out = [];
        foreach (['bootstrap/app.php', 'app/Http/Middleware/VerifyCsrfToken.php'] as $file) {
            if (! $context->files->exists($file)) {
                continue;
            }
            $text = $context->files->text($file);
            if (! preg_match('/(?:validateCsrfTokens\s*\(\s*except\s*:\s*|\$except\s*=\s*)\[(.*?)\]/s', $text, $m, PREG_OFFSET_CAPTURE)) {
                continue;
            }
            $line = substr_count(substr($text, 0, (int) $m[0][1]), "\n") + 1;
            preg_match_all('/[\'"]([^\'"]+)[\'"]/', $m[1][0], $uris);
            foreach ($uris[1] as $uri) {
                $wide = str_contains($uri, '*') && ! str_contains(strtolower($uri), 'webhook');
                $out[] = $this->finding($wide ? Severity::Medium : Severity::Low, "\"$uri\" is excluded from CSRF protection.",
                    'Keep only webhooks that check their own signature there; a form that a user submits needs the CSRF token.', $file, $line, $uri);
            }
        }

        return $out;
    }
}
