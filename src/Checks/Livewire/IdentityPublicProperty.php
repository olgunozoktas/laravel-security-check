<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Livewire;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Livewire\Components;
use Olgun\SecurityCheck\Severity;

/** A public property named for a protected field (email, token, password …) is published and writable by the browser. */
final class IdentityPublicProperty extends LivewireCheck
{
    private const NAMES = ['email', 'payerEmail', 'payerName', 'payerCompany', 'customerEmail', 'firstName', 'lastName', 'surname', 'fullName',
        'phone', 'phoneNumber', 'ssn', 'taxId', 'apiKey', 'secret', 'token', 'password', 'accessToken'];

    public function run(Context $context): array
    {
        $out = [];
        foreach (Components::files($context) as $file) {
            foreach (Components::publicProperties($context->files->lines($file)) as [$line, , $name, $code]) {
                if (in_array($name, self::NAMES, true)) {
                    $out[] = $this->finding(Severity::Low, "The public property \$$name is in the page's wire:snapshot. That is fine for the viewer's OWN input; another person's data must never be there.",
                        'When it holds someone else\'s data, make it protected and pass it to the view; for a secret (token, password, apiKey), never keep it on a public property.', $file, $line, $code);
                }
            }
        }

        return $out;
    }
}
