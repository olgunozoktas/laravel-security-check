<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Livewire;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Livewire\Components;
use Olgun\SecurityCheck\Severity;

/** A public method that changes a record, with no authorization: every public method is callable from the browser console. */
final class UnauthorizedMutator extends LivewireCheck
{
    private const MUTATOR = '/^\s*public\s+function\s+(delete|destroy|remove|update|save|store|approve|reject|refund|publish|unpublish|archive|restore|assign|revoke|impersonate)\w*\s*\(/i';

    // A lifecycle hook is not a mutator: `updatedFoo()` must stay public, and the `update` prefix matched every hook.
    private const LIFECYCLE = '/^\s*public\s+function\s+(updated|updating|mount|boot|booted|hydrate|dehydrate|rendering|rendered)/i';

    public function run(Context $context): array
    {
        $out = [];
        foreach (Components::files($context) as $file) {
            $lines = $context->files->lines($file);
            $bodies = Components::bodies($lines);
            foreach ($lines as $i => $line) {
                if (preg_match(self::LIFECYCLE, $line) === 1 || preg_match(self::MUTATOR, $line) !== 1) {
                    continue;
                }
                $body = implode("\n", array_slice($lines, $i, 40));
                // Only a method that writes a record: one that changes component state alone (removeStep($index)) is not one.
                if (Components::persists($body, $bodies) && ! Components::guarded($body, $bodies)) {
                    $out[] = $this->finding(Severity::High, 'A public method that changes a record has no authorize / Gate / can / policy call. The browser can call it with any argument.',
                        'Resolve the record inside the method and authorize it there: $this->authorize(\'delete\', $post). Make helpers protected or private.', $file, $i + 1, $line);
                }
            }
        }

        return $out;
    }
}
