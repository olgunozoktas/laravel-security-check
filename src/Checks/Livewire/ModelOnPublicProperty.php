<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Livewire;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Livewire\Components;
use Olgun\SecurityCheck\Severity;

/** A public property typed as a model or a collection publishes its class name and primary key in wire:snapshot. */
final class ModelOnPublicProperty extends LivewireCheck
{
    private const HINTS = ['Model', 'Collection', 'EloquentCollection'];

    public function run(Context $context): array
    {
        $out = [];
        foreach (Components::files($context) as $file) {
            foreach (Components::publicProperties($context->files->lines($file)) as [$line, $type, , $code]) {
                $short = $type === '' ? '' : substr((string) strrchr('\\'.$type, '\\'), 1);
                if (in_array($short, self::HINTS, true)) {
                    $out[] = $this->finding(Severity::Low, 'A public property typed as a model or a collection puts its class name and primary key into wire:snapshot, in the page source.',
                        'Keep an id in a #[Locked] public property and load the model in a #[Computed], or register Relation::enforceMorphMap() to hide the class name.', $file, $line, $code);
                }
            }
        }

        return $out;
    }
}
