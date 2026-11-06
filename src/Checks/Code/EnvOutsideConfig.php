<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Code;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** env() outside config/: after php artisan config:cache it answers null, so a secret check or a feature switch goes quiet. */
final class EnvOutsideConfig extends BaseCheck
{
    public function group(): string { return 'code'; }

    public function run(Context $context): array
    {
        $out = [];
        foreach ($context->files->grep($context->files->list(['app', 'routes', 'resources/views'], ['.php']), '/(?<![\w>:$])env\(\s*[\'"]/') as [$file, $line, $code]) {
            $out[] = $this->finding(Severity::Low, 'env() outside config/: after php artisan config:cache it returns null.',
                'Read it in a config file (\'key\' => env(\'X\')) and use config(\'file.key\') in the code.', $file, $line, $code);
        }

        return $out;
    }
}
