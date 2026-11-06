<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Livewire;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Livewire\Components;
use Olgun\SecurityCheck\Severity;

/** A public array bag of page props (props, pageProps, payload, data) publishes the whole bag, often with the logged-in user. */
final class PublicPageProps extends LivewireCheck
{
    public function run(Context $context): array
    {
        $out = [];
        foreach (Components::files($context) as $file) {
            foreach (Components::publicProperties($context->files->lines($file)) as [$line, $type, $name, $code, $above]) {
                if (! str_contains($above, '#[Locked]') && preg_match('/^(pageProps|props|payload|data)$/', $name) === 1 && preg_match('/\barray\b/i', $type) === 1) {
                    $out[] = $this->finding(Severity::Medium, "The public array \$$name publishes the whole prop bag into every page's wire:snapshot, and the browser can change it.",
                        'Make it private (it is then not in the snapshot; set it again on each render).', $file, $line, $code);
                }
            }
        }

        return $out;
    }
}
