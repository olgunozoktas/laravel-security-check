<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Code;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** Raw SQL built from a variable: an SQL injection when the variable comes from the request. */
final class RawSql extends BaseCheck
{
    // A raw call whose first argument interpolates a variable ("... $x ...") or joins one ('...' . $x).
    private const PATTERN = '/(?:DB::raw|DB::(?:select|insert|update|delete|statement|unprepared)|->(?:where|orWhere|having|orHaving|order|orderBy|group|groupBy|select)Raw)\s*\(\s*(?:"[^"]*\{?\$\w[^"]*"|[^,)]*?\.\s*\$\w)/';

    public function group(): string { return 'code'; }

    public function run(Context $context): array
    {
        $out = [];
        foreach ($context->files->grep($context->files->list(['app', 'routes', 'database'], ['.php']), self::PATTERN) as [$file, $line, $code]) {
            // High when the same line reads the request, or a Livewire property (the browser writes those); else an
            // interpolated fragment that the code builds itself (measured 2026-11-06: 19 of 19 such lines in themevault).
            $live = preg_match('/\$request\b|request\(|->input\(|->query\(|\$_(?:GET|POST|REQUEST)|\{\$this->|\.\s*\$this->/', $code) === 1;
            $out[] = $this->finding($live ? Severity::High : Severity::Low,
                $live ? 'Raw SQL is built from request data (or a Livewire property that the browser writes): an SQL injection.'
                    : 'Raw SQL is built from a variable. Confirm that it never holds user input.',
                'Pass the value as a binding: whereRaw("price > ?", [$price]), DB::select("... = ?", [$id]); never put it into the SQL text.', $file, $line, $code);
        }

        return $out;
    }
}
