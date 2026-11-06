<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Alpine;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** $persist writes plain-text localStorage that any script on the origin reads and that survives logout. */
final class PersistedSecret extends AlpineCheck
{
    public function run(Context $context): array
    {
        $files = [...$context->bladeFiles(), ...$context->files->list(['resources/js'], ['.js', '.ts'])];
        $out = [];
        foreach ($context->files->grep($files, '/\b(token|secret|password|apiKey|api_key|role|isAdmin|is_admin|email|session)\w*\s*:\s*(?:this\.)?\$persist\(/i') as [$file, $line, $code]) {
            $out[] = $this->finding(Severity::Medium, '$persist keeps this value in plain-text localStorage: any script on the site reads it, and it stays after logout.',
                'Never persist a token, a role or personal data; keep it on the server. Persist only UI state (a tab, a theme).', $file, $line, $code);
        }

        return $out;
    }
}
