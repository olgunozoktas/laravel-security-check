<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Livewire;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Livewire\Components;
use Olgun\SecurityCheck\Severity;

/** #[Computed(cache: true)] with no key: the cache key holds no user, so every user reads the first user's value. */
final class ComputedCacheWithoutKey extends LivewireCheck
{
    public function run(Context $context): array
    {
        $out = [];
        foreach (Components::files($context) as $file) {
            foreach ($context->files->lines($file) as $i => $line) {
                if (str_contains($line, '#[Computed(') && preg_match('/cache:\s*true/', $line) === 1 && ! str_contains($line, 'key:')) {
                    $out[] = $this->finding(Severity::High, '#[Computed(cache: true)] with no key: Livewire keys it on the component and method names only, so every user reads the first user\'s value for an hour.',
                        'Add a key with the user or tenant (key: \'orders-\'.auth()->id()), or use persist: true for one component instance.', $file, $i + 1, $line);
                }
            }
        }

        return $out;
    }
}
