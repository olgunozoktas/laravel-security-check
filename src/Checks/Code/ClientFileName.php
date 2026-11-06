<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Code;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** An upload stored under the name that the browser sent: "../", ".php" and another user's file name are the client's choice. */
final class ClientFileName extends BaseCheck
{
    public function group(): string { return 'code'; }

    public function run(Context $context): array
    {
        $out = [];
        foreach ($context->files->grep($context->files->list(['app'], ['.php']), '/(?:storeAs|storePubliclyAs|move|putFileAs)\s*\([^;]*getClientOriginalName\(\)/') as [$file, $line, $code]) {
            $out[] = $this->finding(Severity::Medium, 'An upload is stored under the file name that the browser sent.',
                'Store it with a generated name: $file->store(\'dir\') (or hashName()); keep the original name only as data in the database.', $file, $line, $code);
        }

        return $out;
    }
}
