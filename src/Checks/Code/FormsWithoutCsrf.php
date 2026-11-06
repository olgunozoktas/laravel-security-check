<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Code;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Severity;

/** A Blade form that posts with no @csrf: Laravel refuses it (419), or a CSRF exception lets another site post it. */
final class FormsWithoutCsrf extends BaseCheck
{
    public function group(): string { return 'code'; }

    public function run(Context $context): array
    {
        $out = [];
        foreach ($context->bladeFiles() as $file) {
            $lines = $context->files->lines($file);
            foreach ($lines as $i => $line) {
                if (preg_match('/<form\b[^>]*\bmethod\s*=\s*["\']?post/i', $line) !== 1 || preg_match('/wire:submit|x-on:submit|@submit|action\s*=\s*"https?:\/\//i', $line) === 1) {
                    continue;
                }
                $form = implode("\n", array_slice($lines, $i, 30));
                $end = stripos($form, '</form>');
                if (! preg_match('/@csrf|csrf_field\(\)|csrf_token\(\)|name="_token"/', $end === false ? $form : substr($form, 0, $end))) {
                    $out[] = $this->finding(Severity::Medium, 'A POST form with no @csrf.', 'Add @csrf as the form\'s first line.', $file, $i + 1, $line);
                }
            }
        }

        return $out;
    }
}
