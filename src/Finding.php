<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck;

/** One problem that a check found: what, where, and the exact remedy. */
final readonly class Finding
{
    public function __construct(
        public string $check,
        public Severity $severity,
        public string $message,
        public string $remedy,
        public ?string $file = null,
        public ?int $line = null,
        public ?string $code = null,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'check' => $this->check,
            'severity' => $this->severity->value,
            'message' => $this->message,
            'remedy' => $this->remedy,
            'file' => $this->file,
            'line' => $this->line,
            'code' => $this->code,
        ];
    }
}
