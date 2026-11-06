<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Livewire;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Livewire\Components;
use Olgun\SecurityCheck\Severity;

/** A public property with no type: the browser decides what arrives (an array where the code expects a string). */
final class UntypedPublicProperty extends LivewireCheck
{
    public function run(Context $context): array
    {
        $out = [];
        foreach (Components::files($context) as $file) {
            foreach (Components::publicProperties($context->files->lines($file)) as [$line, $type, $name, $code]) {
                if ($type === '' && preg_match('/^\s*public\s+\$/', $code) === 1) {
                    $out[] = $this->finding(Severity::Low, "public \$$name has no type: the browser can send an array or a number where the code expects a string.",
                        'Give it a type (public string $'.$name.' = \'\';) and validate it.', $file, $line, $code);
                }
            }
        }

        return $out;
    }
}
