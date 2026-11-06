<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Alpine;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/**
 * Server output inside an Alpine EXPRESSION attribute (alpinejs-security, seam B; its reviewer's rule
 * `server-interp-in-expression`). HTML-escaping does not protect it: the browser decodes &#039; back to a quote before
 * Alpine compiles the attribute, so a value with a quote runs as code. It flags the PATTERN: a hard-coded loop
 * constant is latent, a user-supplied field is live; fix it either way.
 */
final class BladeInAlpineExpression extends AlpineCheck
{
    public function run(Context $context): array
    {
        $rx = '/(?<![\w:.-])(?P<attr>'.AlpineSource::EXPR_ATTRS.')\s*=\s*(?P<q>["\'])(?P<val>(?:(?!(?P=q)).)*?'.AlpineSource::INTERP.'(?:(?!(?P=q)).)*?)(?P=q)/s';
        $out = [];
        foreach ($context->bladeFiles() as $file) {
            $text = $context->files->text($file);
            if (preg_match_all($rx, $text, $all, PREG_SET_ORDER | PREG_OFFSET_CAPTURE) === 0) {
                continue;
            }
            $seen = [];
            foreach ($all as $m) {
                [$whole, $at] = $m[0];
                if (AlpineSource::looksLikePhp($whole) || AlpineSource::encoded($whole)) {
                    continue;
                }
                $line = substr_count($text, "\n", 0, $at) + 1;
                if (isset($seen[$line])) {
                    continue;
                }
                $seen[$line] = true;
                $out[] = $this->finding(Severity::Medium, "Server data inside the Alpine expression {$m['attr'][0]}: HTML-escaping does not protect JavaScript, so a value with a quote runs as code (latent for a hard-coded value, live for a user's).",
                    'Encode it for JavaScript: @js($value) / Js::from($value), or pass it as data-x="{{ $value }}" and read $el.dataset.x. Fix it either way: the pattern becomes a hole the day the source changes.', $file, $line, strtok($whole, "\n"));
            }
        }

        return $out;
    }
}
