<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Alpine;

/**
 * The attribute rules of the alpinejs-security skill's reviewer (bin/review-security.py), ported as they are: which
 * attributes Alpine compiles, which server interpolations it sees, and the filter that tells a Blade component's PHP
 * binding (`<x-button :label="$x">`) from an Alpine expression. The skill MEASURED that without that filter its URL rule
 * produced 14 findings on a 343-template application, and all 14 were Blade bindings.
 */
final class AlpineSource
{
    /** A server-template interpolation of any common engine. */
    public const INTERP = '(?:\{\{(?!--).*?\}\}|\{!!.*?!!\}|<\?=.*?\?>)';

    /** Alpine attributes whose value Alpine COMPILES as JavaScript (seam B). */
    public const EXPR_ATTRS = 'x-data|x-init|x-effect|x-show|x-if|x-for|x-text|x-model|x-modelable|x-id|x-teleport|x-on:[\w.\-]+|@[\w.\-]+|x-bind:[\w.\-]+|:[\w.\-]+';

    private const MAGICS = ['$el', '$refs', '$store', '$watch', '$dispatch', '$nextTick', '$id', '$root', '$data', '$persist', '$queryString', '$wire'];

    /** True when an attribute's value is PHP (a Blade component binding) rather than an Alpine expression. */
    public static function looksLikePhp(string $fragment): bool
    {
        if (preg_match('/->|::|\b(?:__|e|route|url|asset|trans|config)\s*\(/', $fragment) === 1) {
            return true;
        }
        if (preg_match('/=\s*["\']\s*(?P<head>[^\s"\']{0,40})/', $fragment, $m) !== 1) {
            return false;
        }

        return preg_match('/^\$\w+/', $m['head'], $d) === 1 && ! in_array($d[0], self::MAGICS, true);
    }

    /** True when the value is already encoded for JavaScript. */
    public static function encoded(string $fragment): bool
    {
        return preg_match('/@js\s*\(|Js::from|json_encode|\|\s*json|@json\b/', $fragment) === 1;
    }
}
