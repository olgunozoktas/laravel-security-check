<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Code;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** {!! !!} prints HTML without escaping it: an XSS when any part of it comes from a user. */
final class UnescapedBlade extends BaseCheck
{
    public function group(): string { return 'code'; }

    public function run(Context $context): array
    {
        $safe = (string) $context->config('security-check.safe_raw_output', '/^$/');
        $out = [];
        foreach ($context->files->grep($context->bladeFiles(), '/\{!!.+?!!\}/') as [$file, $line, $code]) {
            preg_match_all('/\{!!\s*(.+?)\s*!!\}/', $code, $m);
            foreach ($m[1] as $inner) {
                if (@preg_match($safe, $inner) === 1 || preg_match('/^file_get_contents\(\s*(?:resource_path|base_path|public_path)\(/', $inner) === 1) {
                    continue;  // the app's own file, not a user's text
                }
                // JSON in a <script>: not HTML, but "</script>" in the data ends the script unless JSON_HEX_TAG is set.
                if (preg_match('/^(?:json_encode|(?:\\\\?Illuminate\\\\Support\\\\)?Js::from)\(/', $inner) === 1) {
                    if (! str_contains($inner, 'JSON_HEX_TAG') && ! str_contains($inner, 'Js::from')) {
                        $out[] = $this->finding(Severity::Low, 'JSON printed with {!! !!}: a "</script>" inside the data ends the script.', 'Add JSON_HEX_TAG (json_encode($data, JSON_HEX_TAG | …)), or use @js / Js::from.', $file, $line, $code);
                    }

                    continue;
                }
                $out[] = $this->finding(Severity::Medium, "Unescaped output {!! $inner !!}: if any part comes from a user, a script runs in every visitor's browser.",
                    'Use {{ }} . If the HTML is wanted, clean it first (for example with a purifier) and add the pattern to security-check.safe_raw_output.', $file, $line, $code);
            }
        }

        return $out;
    }
}
