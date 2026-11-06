<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck;

/** How bad a finding is. `--fail-on` names the lowest one that makes the command exit non-zero. */
enum Severity: string
{
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case Info = 'info';

    public function rank(): int
    {
        return match ($this) {
            self::High => 3,
            self::Medium => 2,
            self::Low => 1,
            self::Info => 0,
        };
    }
}
