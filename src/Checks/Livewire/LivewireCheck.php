<?php

declare(strict_types=1);

namespace Olgun\SecurityCheck\Checks\Livewire;

use Olgun\SecurityCheck\BaseCheck;
use Olgun\SecurityCheck\Context;

/** A Livewire check: it applies only when the app has Livewire. */
abstract class LivewireCheck extends BaseCheck
{
    public function group(): string { return 'livewire'; }

    public function applies(Context $context): bool
    {
        return $context->hasLivewire();
    }
}
