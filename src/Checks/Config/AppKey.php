<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Config;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** APP_KEY signs and encrypts cookies, sessions and signed URLs: it must be set and 32 random bytes. */
final class AppKey extends BaseCheck
{
    public function group(): string { return 'config'; }

    public function run(Context $context): array
    {
        $key = (string) $context->config('app.key');
        $bytes = str_starts_with($key, 'base64:') ? strlen((string) base64_decode(substr($key, 7), true)) : strlen($key);
        if ($key === '') {
            return [$this->finding(Severity::High, 'APP_KEY is empty: Laravel cannot encrypt cookies and sessions safely.', 'Run php artisan key:generate (once; a new key logs out every user).', '.env')];
        }
        if ($bytes < 32) {
            return [$this->finding(Severity::High, "APP_KEY is {$bytes} bytes; it must be 32 bytes for AES-256.", 'Run php artisan key:generate (a new key logs out every user and breaks data that the old key encrypted).', '.env')];
        }

        return [];
    }
}
