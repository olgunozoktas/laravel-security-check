<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Livewire;

use Olgun\SecurityCheck\Context;
use Olgun\SecurityCheck\Livewire\Components;
use Olgun\SecurityCheck\Severity;

/** A #[Url] property that selects a record, with no #[Locked]: any link sets the record that the component reads. */
final class UrlWritableIdentifier extends LivewireCheck
{
    private const IDS = ['id', 'uuid', 'key', 'recordId', 'modelId', 'postId', 'userId', 'accountId', 'teamId', 'orderId', 'paymentId'];

    public function run(Context $context): array
    {
        $out = [];
        foreach (Components::files($context) as $file) {
            foreach (Components::publicProperties($context->files->lines($file)) as [$line, , $name, $code, $above]) {
                if (str_contains($above, '#[Url') && ! str_contains($above, '#[Locked]') && in_array($name, self::IDS, true)) {
                    $out[] = $this->finding(Severity::Medium, "#[Url] public \$$name selects a record from the address bar: any link can choose which record the component reads.",
                        'Authorize the record that it loads, on every request (mount() and each action), or take it from route model binding.', $file, $line, $code);
                }
            }
        }

        return $out;
    }
}
