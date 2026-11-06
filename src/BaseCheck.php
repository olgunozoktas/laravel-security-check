<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck;

/** The shared parts of a check: its name from the class, and a short way to make a finding. */
abstract class BaseCheck implements Check
{
    public function name(): string
    {
        $short = substr((string) strrchr('\\'.static::class, '\\'), 1);

        return strtolower((string) preg_replace('/(?<!^)[A-Z]/', '-$0', $short));
    }

    public function applies(Context $context): bool
    {
        return true;
    }

    protected function finding(Severity $severity, string $message, string $remedy, ?string $file = null, ?int $line = null, ?string $code = null): Finding
    {
        return new Finding($this->name(), $severity, $message, $remedy, $file, $line, $code === null ? null : mb_substr(trim($code), 0, 200));
    }
}
